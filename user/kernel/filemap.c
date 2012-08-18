/*
 * Map logical file extents to physical disk
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 2
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

/*
 * Locking order: Take care about memory allocation. (It may call our fs.)
 *
 * down_write(itable: btree->lock) (open_inode)
 * down_read(itable: btree->lock) (make_inode, save_inode)
 *    balloc()
 *
 * down_write(inode: btree->lock) (btree_chop, map_region for write)
 *     bitmap->i_mutex (balloc, bfree)
 *         down_read(bitmap: btree->lock) (map_region for read)
 * down_read(inode: btree->lock) (map_region for read)
 *
 * This lock may be first lock except vfs locks (lock_super, i_mutex).
 * sb->delta_lock (change_begin, change_end)
 *
 * This lock may be last lock. (care about blockget())
 * sb->loglock (log_begin, log_end)
 *
 * memory allocation: (blockread, blockget, kmalloc, etc.)
 *     lock_page() (for write)
 *         write (bitmap) dirty buffers:
 *             down_write(bitmap: btree->lock) (map_region for write)
 *                 lock_page() (blockread)
 *                     Note, this down_read is avoided by is_bitmap_write()
 *                     [down_read(bitmap: btree->lock) (map_region for read)]
 *                 bitmap->i_mutex (balloc)
 *
 *     lock_page() (blockread)
 *         down_read(bitmap: btree->lock) (map_region for read)
 *     bitmap->i_mutex (balloc)
 *
 * So, to prevent reentering into our fs recursively by memory reclaim
 * from memory allocation, lower layer wouldn't use __GFP_FS.
 */

#include "tux3.h"
#include "dleaf2.h"

#ifndef trace
#define trace trace_on
#endif

enum map_mode {
	MAP_READ	= 0,	/* map_region for read */
	MAP_WRITE	= 1,	/* map_region for overwrite */
	MAP_REDIRECT	= 2,	/* map_region for redirected write
				 * (copy-on-write) */
};

#if 1
/* FIXME: this is temporary fix */
#ifndef __KERNEL__
static struct { void *journal_info; } __current, *current = &__current;
#endif
static void get_bitmap_write(struct sb *sb)
{
	current->journal_info = sb->bitmap;
}

static int is_bitmap_write(struct sb *sb)
{
	return current->journal_info == sb->bitmap;
}

static void put_bitmap_write(struct sb *sb)
{
	current->journal_info = NULL;
}
#endif

/* userland only */
void show_segs(struct seg map[], unsigned segs)
{
	printf("%i segs: ", segs);
	for (int i = 0; i < segs; i++)
		printf("%Lx/%i ", map[i].block, map[i].count);
	printf("\n");
}

static int map_bfree(struct inode *inode, block_t block, unsigned count)
{
	struct sb *sb = tux_sb(inode->i_sb);
	if (inode == sb->bitmap) {
		log_bfree_on_rollup(sb, block, count);
		defer_bfree(&sb->derollup, block, count);
	} else {
		log_bfree(sb, block, count);
		defer_bfree(&sb->defree, block, count);
	}
	return 0;
}

/* map_region() by using dleaf1 */
static int map_region1(struct inode *inode, block_t start, unsigned count,
		       struct seg map[], unsigned max_segs, enum map_mode mode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *btree = &tux_inode(inode)->btree;
	struct cursor *cursor = NULL;
	int err, segs = 0;

	assert(max_segs > 0);

	if (mode != MAP_READ) {
		down_write(&btree->lock);
		if (inode == sb->bitmap)
			get_bitmap_write(sb);
	} else {
		if (!is_bitmap_write(sb))
			down_read_nested(&btree->lock, inode == sb->bitmap);
	}

	if (!has_root(btree) && mode != MAP_READ) {
		/*
		 * Allocate empty btree if this btree doesn't have it yet.
		 * FIXME: this should be merged to insert_leaf() or something?
		 */
		err = alloc_empty_btree(btree);
		if (err) {
			segs = err;
			goto out_unlock;
		}
	}

	/* dwalk_end(walk) is true with this. */
	struct dwalk *walk = &(struct dwalk){ };
	struct dleaf *leaf = NULL;
	if (has_root(btree)) {
		cursor = alloc_cursor(btree, 1); /* allows for depth increase */
		if (!cursor) {
			segs = -ENOMEM;
			goto out_unlock;
		}

		if ((err = btree_probe(cursor, start))) {
			segs = err;
			goto out_unlock;
		}
		leaf = bufdata(cursor_leafbuf(cursor));
		dleaf_dump(btree, leaf);
		dwalk_probe(leaf, sb->blocksize, walk, start);
	} else {
		assert(mode == MAP_READ);
		/* btree doesn't have root yet */
	}

	block_t limit = start + count;
	if (cursor) {
		assert(start >= cursor_this_key(cursor));
		/* do not overlap next leaf */
		if (limit > cursor_next_key(cursor))
			limit = cursor_next_key(cursor);
	}
	trace("--- index %Lx, limit %Lx ---", start, limit);

	block_t index = start, seg_start, block;
	struct dwalk headwalk = *walk;
	if (!dwalk_end(walk) && dwalk_index(walk) < start)
		seg_start = dwalk_index(walk);
	else
		seg_start = index;
	while (index < limit && segs < max_segs) {
		block_t ex_index;
		if (!dwalk_end(walk))
			ex_index = dwalk_index(walk);
		else
			ex_index = limit;

		if (index < ex_index) {
			/* There is hole */
			ex_index = min(ex_index, limit);
			unsigned gap = ex_index - index;
			index = ex_index;
			map[segs++] = (struct seg){ .count = gap, .state = SEG_HOLE };
		} else {
			block = dwalk_block(walk);
			count = dwalk_count(walk);
			trace("emit %Lx/%x", block, count);
			map[segs++] = (struct seg){ .block = block, .count = count };
			index = ex_index + count;
			dwalk_next(walk);
 		}
	}
	assert(segs);
	unsigned below = start - seg_start, above = index - min(index, limit);
	map[0].block += below;
	map[0].count -= below;
	map[segs - 1].count -= above;

	if (mode == MAP_READ)
		goto out_release;

	/* Save blocks before change map[] for below or above. */
	block_t below_block, above_block;
	below_block = map[0].block - below;
	above_block = map[segs - 1].block + map[segs - 1].count;
	if (mode == MAP_REDIRECT) {
		/* Change the map[] to redirect this region as one extent */
		count = 0;
		for (int i = 0; i < segs; i++) {
			/* Logging overwrited extents as free */
			if (map[i].state != SEG_HOLE)
				map_bfree(inode, map[i].block, map[i].count);
			count += map[i].count;
		}
		segs = 1;
		map[0].block = 0;
		map[0].count = count;
		map[0].state = SEG_HOLE;
	}
	for (int i = 0; i < segs; i++) {
		if (map[i].state != SEG_HOLE)
			continue;

		count = map[i].count;
		if ((err = balloc(sb, count, &block))) { // goal ???
			/*
			 * Out of space on file data allocation.  It happens.  Tread
			 * carefully.  We have not stored anything in the btree yet,
			 * so we free what we allocated so far.  We need to leave the
			 * user with a nice ENOSPC return and all metadata consistent
			 * on disk.  We better have reserved everything we need for
			 * metadata, just giving up is not an option.
			 */
			/*
			 * Alternatively, we can go ahead and try to record just what
			 * we successfully allocated, then if the update fails on no
			 * space for btree splits, free just the blocks for extents
			 * we failed to store.
			 */
			segs = err;
			goto out_release;
		}
		log_balloc(sb, block, count);
		trace("fill in %Lx/%i ", block, count);

		map[i].block = block;
		map[i].count = count;
		/* if mode == MAP_REDIRECT, buffer should be dirty */
		map[i].state = (mode == MAP_REDIRECT) ? 0 : SEG_NEW;
	}

	/* Start to reflect the map[] changes to the data btree */
	if ((err = cursor_redirect(cursor))) {
		segs = err;
		goto out_release;
	}
	/* Update redirected place for local variables */
	dwalk_redirect(walk, leaf, bufdata(cursor_leafbuf(cursor)));
	dwalk_redirect(&headwalk, leaf, bufdata(cursor_leafbuf(cursor)));
	leaf = bufdata(cursor_leafbuf(cursor));

	struct dleaf *tail = NULL;
	tuxkey_t tailkey = 0; // probably can just use limit instead
	if (!dwalk_end(walk)) {
		tail = malloc(sb->blocksize); // error???
		dleaf_init(btree, tail);
		tailkey = dwalk_index(walk);
		dwalk_copy(walk, tail);
	}
	/* Go back to region start and pack in new segs */
	dwalk_chop(&headwalk);
	index = start;
	for (int i = -!!below; i < segs + !!above; i++) {
		if (dleaf_free(btree, leaf) < DLEAF_MAX_EXTENT_SIZE) {
			mark_buffer_dirty_non(cursor_leafbuf(cursor));
			struct buffer_head *newbuf = new_leaf(btree);
			if (IS_ERR(newbuf)) {
				segs = PTR_ERR(newbuf);
				goto out_create;
			}
			log_balloc(sb, bufindex(newbuf), 1);
			/*
			 * ENOSPC on btree index split could leave the
			 * cache state badly messed up.  Going to have
			 * to do this in two steps: first, look at the
			 * cursor to see how many splits we need, then
			 * make sure we have that, or give up before
			 * starting.
			 */
			btree_insert_leaf(cursor, index, newbuf);
			leaf = bufdata(cursor_leafbuf(cursor));
			dwalk_probe(leaf, sb->blocksize, &headwalk, index);
		}
		if (i < 0) {
			trace("emit below");
			dwalk_add(&headwalk, seg_start, make_extent(below_block, below));
			continue;
		}
		if (i == segs) {
			trace("emit above");
			dwalk_add(&headwalk, index, make_extent(above_block, above));
			continue;
		}
		trace("pack 0x%Lx => %Lx/%x", index, map[i].block, map[i].count);
		dleaf_dump(btree, leaf);
		dwalk_add(&headwalk, index, make_extent(map[i].block, map[i].count));
		dleaf_dump(btree, leaf);
		index += map[i].count;
	}
	if (tail) {
		if (!dleaf_merge(btree, leaf, tail)) {
			mark_buffer_dirty_non(cursor_leafbuf(cursor));
			assert(dleaf_groups(tail) >= 1);
			/* Tail does not fit, add it as a new btree leaf */
			struct buffer_head *newbuf = new_leaf(btree);
			if (IS_ERR(newbuf)) {
				segs = PTR_ERR(newbuf);
				goto out_create;
			}
			memcpy(bufdata(newbuf), tail, sb->blocksize);
			log_balloc(sb, bufindex(newbuf), 1);
			if ((err = btree_insert_leaf(cursor, tailkey, newbuf))) {
				segs = err;
				goto out_create;
			}
		}
	}
	mark_buffer_dirty_non(cursor_leafbuf(cursor));
out_create:
	if (tail)
		free(tail);
out_release:
	if (cursor)
		release_cursor(cursor);
out_unlock:
	if (mode != MAP_READ) {
		up_write(&btree->lock);
		if (inode == sb->bitmap)
			put_bitmap_write(sb);
	} else {
		if (!is_bitmap_write(sb))
			up_read(&btree->lock);
	}
	if (cursor)
		free_cursor(cursor);

	return segs;
}

/* map_region() by using dleaf2 */
static int map_region2(struct inode *inode, block_t start, unsigned count,
		       struct seg seg[], unsigned max_segs, enum map_mode mode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *btree = &tux_inode(inode)->btree;
	struct cursor *cursor = NULL;
	int err, segs = 0;

	assert(max_segs > 0);

	if (mode != MAP_READ) {
		down_write(&btree->lock);
		if (inode == sb->bitmap)
			get_bitmap_write(sb);
	} else {
		if (!is_bitmap_write(sb))
			down_read_nested(&btree->lock, inode == sb->bitmap);
	}

	if (!has_root(btree) && mode != MAP_READ) {
		/*
		 * Allocate empty btree if this btree doesn't have it yet.
		 * FIXME: this should be merged to insert_leaf() or something?
		 */
		err = alloc_empty_btree(btree);
		if (err) {
			segs = err;
			goto out_unlock;
		}
	}

	if (has_root(btree)) {
		struct dleaf_req rq = {
			.key = {
				.start	= start,
				.len	= count,
			},
			.max_segs	= max_segs,
			.seg		= seg,
		};

		cursor = alloc_cursor(btree, 1); /* allows for depth increase */
		if (!cursor) {
			segs = -ENOMEM;
			goto out_unlock;
		}

		err = btree_probe(cursor, start);
		if (err) {
			segs = err;
			goto out_unlock;
		}
		/* Read extents from data btree */
		err = btree_read(cursor, &rq.key);
		if (err) {
			segs = err;
			goto out_unlock;
		}
		segs = rq.nr_segs;
		/*
		 * Read might be partial. (due to max_segs, or FIXME:
		 * lack of read for multiple leaves)
		 */
		count = seg_total_count(seg, segs);
	} else {
		assert(mode == MAP_READ);
		/* btree doesn't have root yet */
		segs = 1;
		seg[0].block = 0;
		seg[0].count = count;
		seg[0].state = SEG_HOLE;
	}
	assert(segs);

	if (mode == MAP_READ)
		goto out_release;

	if (mode == MAP_REDIRECT) {
		/* Change the seg[] to redirect this region as one extent */
		unsigned total = 0;
		for (int i = 0; i < segs; i++) {
			/* Logging overwrited extents as free */
			if (seg[i].state != SEG_HOLE)
				map_bfree(inode, seg[i].block, seg[i].count);
			total += seg[i].count;
		}
		assert(total == count);
		segs = 1;
		seg[0].block = 0;
		seg[0].count = total;
		seg[0].state = SEG_HOLE;
	}
	for (int i = 0; i < segs; i++) {
		block_t block;

		if (seg[i].state != SEG_HOLE)
			continue;

		err = balloc(sb, seg[i].count, &block);
		if (err) { // goal ???
			/*
			 * Out of space on file data allocation.  It
			 * happens.  Tread carefully.  We have not
			 * stored anything in the btree yet, so we
			 * free what we allocated so far.  We need to
			 * leave the user with a nice ENOSPC return
			 * and all metadata consistent on disk.  We
			 * better have reserved everything we need for
			 * metadata, just giving up is not an option.
			 */
			/*
			 * Alternatively, we can go ahead and try to
			 * record just what we successfully allocated,
			 * then if the update fails on no space for
			 * btree splits, free just the blocks for
			 * extents we failed to store.
			 */
			segs = err;
			goto out_release;
		}
		log_balloc(sb, block, seg[i].count);

		seg[i].block = block;
		/* if mode == MAP_REDIRECT, buffer should be dirty */
		seg[i].state = (mode == MAP_REDIRECT) ? 0 : SEG_NEW;
	}

	/* Write extents from data btree */
	struct dleaf_req rq = {
		.key = {
			.start	= start,
			.len	= count,
		},
		.max_segs	= segs,
		.seg		= seg,
	};
	err = btree_write(cursor, &rq.key);
	if (err) {
		segs = err;
		goto out_release;
	}
	assert(segs == rq.nr_segs);

out_release:
	if (cursor)
		release_cursor(cursor);
out_unlock:
	if (mode != MAP_READ) {
		up_write(&btree->lock);
		if (inode == sb->bitmap)
			put_bitmap_write(sb);
	} else {
		if (!is_bitmap_write(sb))
			up_read(&btree->lock);
	}
	if (cursor)
		free_cursor(cursor);

	return segs;
}

/*
 * Map logical extent to physical extent
 *
 * return value:
 * < 0 - error
 * 0 < - number of physical extents which were mapped
 */
static int map_region(struct inode *inode, block_t start, unsigned count,
		      struct seg map[], unsigned max_segs, enum map_mode mode)
{
	struct btree *btree = &tux_inode(inode)->btree;

	if (btree->ops == &dtree1_ops)
		return map_region1(inode, start, count, map, max_segs, mode);
	else
		return map_region2(inode, start, count, map, max_segs, mode);
}

#ifdef __KERNEL__
#include <linux/mpage.h>

/* create modes: 0 - read, 1 - write, 2 - redirect, 3 - delalloc */
static int __tux3_get_block(struct inode *inode, sector_t iblock,
			    struct buffer_head *bh_result, int create)
{
	trace("==> inum %Lu, iblock %Lu, b_size %zu, create %d",
	      tux_inode(inode)->inum, iblock, bh_result->b_size, create);

	struct sb *sb = tux_sb(inode->i_sb);
	size_t max_blocks = bh_result->b_size >> inode->i_blkbits;
	struct btree *btree = &tux_inode(inode)->btree;
	enum map_mode mode;

	if (sb->logmap == inode) {
		assert(!has_root(btree) && create);
		return 0;
	}

	int delalloc;
	if (create == 3) {
		delalloc = 1;
		mode = MAP_READ;
	} else {
		delalloc = 0;
		mode = create;
	}

	struct seg seg;
	int segs = map_region(inode, iblock, max_blocks, &seg, 1, mode);
	if (segs < 0) {
		warn("map_region failed: %d", -segs);
		return -EIO;
	}
	assert(segs == 1);
	size_t blocks = min_t(size_t, max_blocks, seg.count);
	switch (seg.state) {
	case SEG_HOLE:
		if (delalloc && !buffer_delay(bh_result)) {
			map_bh(bh_result, inode->i_sb, 0);
			set_buffer_new(bh_result);
			set_buffer_delay(bh_result);
			bh_result->b_size = blocks << sb->blockbits;
		}
		break;
	case SEG_NEW:
		assert(create && !delalloc);
		assert(seg.block);
		if (buffer_delay(bh_result)) {
			/* for now, block_write_full_page() clear delay */
//			clear_buffer_delay(bh_result);
			bh_result->b_blocknr = seg.block;
			/*
			 * FIXME: do we need to unmap_underlying_metadata()
			 * for sb->volmap? (at least, check buffer state?)
			 * And if needed, is it enough?
			 */
			break;
		}
		set_buffer_new(bh_result);
		/* FALLTHROUGH */
	default:
		map_bh(bh_result, inode->i_sb, seg.block);
		bh_result->b_size = blocks << sb->blockbits;
		break;
	}
	trace("<== inum %Lu, mapped %d, block %Lu, size %zu",
	      tux_inode(inode)->inum, buffer_mapped(bh_result),
	      bh_result->b_blocknr, bh_result->b_size);

	return 0;
}

static int tux3_da_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh_result, int create)
{
	/* FIXME: We should reserve the space */
	return __tux3_get_block(inode, iblock, bh_result, 3);
}

int tux3_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create)
{
	return __tux3_get_block(inode, iblock, bh_result, create);
}

static struct buffer_head *find_get_buffer(struct page *page, int offset)
{
	struct buffer_head *bh = page_buffers(page);

	while (offset--)
		bh = bh->b_this_page;
	get_bh(bh);
	return bh;
}

static struct buffer_head *get_buffer(struct address_space *mapping,
				      pgoff_t index, int offset)
{
	struct buffer_head *bh = NULL;
	struct page *page;

	page = find_get_page(mapping, index);
	if (page) {
		if (PageUptodate(page)) {
			spin_lock(&mapping->private_lock);
			if (page_has_buffers(page)) {
				bh = find_get_buffer(page, offset);
				assert(buffer_uptodate(bh));
			}
			spin_unlock(&mapping->private_lock);
		}
		page_cache_release(page);
	}
	return bh;
}

struct buffer_head *blockread(struct address_space *mapping, block_t iblock)
{
	struct inode *inode = mapping->host;
	gfp_t gfp_mask = mapping_gfp_mask(mapping) | __GFP_COLD; /* FIXME(?) */
	pgoff_t index;
	struct page *page;
	struct buffer_head *bh;
	int err, offset;

	index = iblock >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	offset = iblock & ((1 << (PAGE_CACHE_SHIFT - inode->i_blkbits)) - 1);

	bh = get_buffer(mapping, index, offset);
	if (bh)
		return bh;

	err = -ENOMEM;
	/* FIXME: don't need to find again. Just try to allocate and insert */
	page = find_or_create_page(mapping, index, gfp_mask);
	if (!page)
		goto error;

	if (!page_has_buffers(page))
		create_empty_buffers(page, tux_sb(inode->i_sb)->blocksize, 0);
	bh = find_get_buffer(page, offset);

	if (PageUptodate(page))
		unlock_page(page);
	else {
		err = mapping->a_ops->readpage(NULL, page);
		if (err)
			goto error_readpage;
		wait_on_page_locked(page);
		if (!PageUptodate(page)) {
			err = -EIO;
			goto error_readpage;
		}
	}
	page_cache_release(page);
	assert(buffer_uptodate(bh));

	return bh;

error_readpage:
	put_bh(bh);
	page_cache_release(page);
error:
	return NULL;
}

struct buffer_head *blockget(struct address_space *mapping, block_t iblock)
{
	struct inode *inode = mapping->host;
	pgoff_t index;
	struct page *page;
	struct buffer_head *bh;
	void *fsdata;
	int err, offset;
	unsigned aop_flags = AOP_FLAG_UNINTERRUPTIBLE;

	index = iblock >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	offset = iblock & ((1 << (PAGE_CACHE_SHIFT - inode->i_blkbits)) - 1);

	/* Prevent reentering into our fs recursively by memory allocation. */
	if (!(mapping_gfp_mask(mapping) & __GFP_FS))
		aop_flags |= AOP_FLAG_NOFS;

	err = mapping->a_ops->write_begin(NULL, mapping,
					  iblock << inode->i_blkbits,
					  1 << inode->i_blkbits,
					  aop_flags, &page, &fsdata);
	if (err)
		return NULL;

	assert(page_has_buffers(page));

	bh = find_get_buffer(page, offset);
	set_buffer_uptodate(bh);

	unlock_page(page);
	page_cache_release(page);

	return bh;
}

static int tux3_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, tux3_get_block);
}

static int tux3_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, tux3_get_block);
}

static int tux3_da_write_begin(struct file *file, struct address_space *mapping,
			       loff_t pos, unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				tux3_da_get_block);
	if (ret < 0)
		tux3_write_failed(mapping, pos + len);
	return ret;
}

static int tux3_da_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	int ret;

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret < len)
		tux3_write_failed(mapping, pos + len);
	return ret;
}

static int tux3_writepage(struct page *page, struct writeback_control *wbc)
{
	struct sb *sb = tux_sb(page->mapping->host->i_sb);
	change_begin(sb);
	int err = block_write_full_page(page, tux3_get_block, wbc);

	change_end(sb);
	return err;
}
#if 0
/* mpage_writepages() uses dummy bh, so we can't check buffer_delay. */
static int tux3_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, tux3_get_block);
}
#endif
static ssize_t tux3_direct_IO(int rw, struct kiocb *iocb,
			      const struct iovec *iov,
			      loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;

	ret = blockdev_direct_IO(rw, iocb, inode, iov, offset, nr_segs,
				 tux3_get_block);
	if (ret < 0 && (rw & WRITE))
		tux3_write_failed(mapping, offset + iov_length(iov, nr_segs));
	return ret;
}

static sector_t tux3_bmap(struct address_space *mapping, sector_t iblock)
{
	sector_t blocknr;

	mutex_lock(&mapping->host->i_mutex);
	blocknr = generic_block_bmap(mapping, iblock, tux3_get_block);
	mutex_unlock(&mapping->host->i_mutex);

	return blocknr;
}

const struct address_space_operations tux_aops = {
	.readpage		= tux3_readpage,
	.readpages		= tux3_readpages,
	.writepage		= tux3_writepage,
//	.writepages		= tux3_writepages,
	.write_begin		= tux3_da_write_begin,
	.write_end		= tux3_da_write_end,
	.bmap			= tux3_bmap,
//	.invalidatepage		= ext4_da_invalidatepage,
//	.releasepage		= ext4_releasepage,
	.direct_IO		= tux3_direct_IO,
	.migratepage		= buffer_migrate_page,
//	.is_partially_uptodate	= block_is_partially_uptodate,
};

static int tux3_blk_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, tux3_get_block);
}

static int tux3_blk_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, tux3_get_block, wbc);
}

const struct address_space_operations tux_blk_aops = {
	.readpage	= tux3_blk_readpage,
	.writepage	= tux3_blk_writepage,
//	.writepages	= tux3_writepages,
	.write_begin	= tux3_da_write_begin,
	.bmap		= tux3_bmap,
};

static int tux3_vol_get_block(struct inode *inode, sector_t iblock,
			      struct buffer_head *bh_result, int create)
{
	if (iblock >= tux_sb(inode->i_sb)->volblocks) {
		assert(!create);
		return 0;
	}
	map_bh(bh_result, inode->i_sb, iblock);
	return 0;
}

static int tux3_vol_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, tux3_vol_get_block);
}

static int tux3_vol_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, tux3_vol_get_block, wbc);
}

static int tux3_vol_write_begin(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	return block_write_begin(mapping, pos, len, flags, pagep,
				 tux3_vol_get_block);
}

const struct address_space_operations tux_vol_aops = {
	.readpage	= tux3_vol_readpage,
	.writepage	= tux3_vol_writepage,
	.write_begin	= tux3_vol_write_begin,
};
#endif /* __KERNEL__ */
