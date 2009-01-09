#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

#define SEG_HOLE	(1 << 0)
#define SEG_NEW		(1 << 1)

struct seg { block_t block; unsigned count; unsigned state; };

/* userland only */
void show_segs(struct seg map[], unsigned segs)
{
	printf("%i segs: ", segs);
	for (int i = 0; i < segs; i++)
		printf("%Lx/%i ", (L)map[i].block, map[i].count);
	printf("\n");
}

static int map_region(struct inode *inode, block_t start, unsigned count, struct seg map[], unsigned max_segs, int create)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct cursor *cursor = alloc_cursor(&tux_inode(inode)->btree, 1); /* allows for depth increase */
	if (!cursor)
		return -ENOMEM;

	if (create)
		down_write(&cursor->btree->lock);
	else
		down_read(&cursor->btree->lock);

	assert(max_segs > 0);
	block_t limit = start + count;
	trace("--- index %Lx, limit %Lx ---", (L)start, (L)limit);
	struct btree *btree = cursor->btree;
	int err, segs = 0;

	if (!btree->root.depth)
		goto out_unlock;

	if ((err = probe(btree, start, cursor))) {
		segs = err;
		goto out_unlock;
	}
	//assert(start >= this_key(cursor, btree->root.depth))
	/* do not overlap next leaf */
	if (limit > next_key(cursor, btree->root.depth))
		limit = next_key(cursor, btree->root.depth);
	struct dleaf *leaf = bufdata(cursor_leafbuf(cursor));
	dleaf_dump(btree, leaf);

	struct dwalk *walk = &(struct dwalk){ };
	block_t index = start, seg_start, block;
	dwalk_probe(leaf, sb->blocksize, walk, start);
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
			trace("emit %Lx/%x", (L)block, count );
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

	if (!create)
		goto out_release;

	struct dleaf *tail = NULL;
	tuxkey_t tailkey = 0; // probably can just use limit instead

	if (!dwalk_end(walk)) {
		tail = malloc(sb->blocksize); // error???
		dleaf_init(btree, tail);
		tailkey = dwalk_index(walk);
		dwalk_copy(walk, tail);
	}

	for (int i = 0; i < segs; i++) {
		if (map[i].state == SEG_HOLE) {
			count = map[i].count;
			block = balloc(sb, count); // goal ???
			trace("fill in %Lx/%i ", (L)block, count);
			if (block == -1) {
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
				segs = -ENOSPC;
				goto out_create;
			}
			map[i] = (struct seg){ .block = block, .count = count, .state = SEG_NEW, };
		}
	}
	/* Go back to region start and pack in new segs */
	dwalk_chop(&headwalk);
	index = start;
	for (int i = -!!below; i < segs + !!above; i++) {
		if (dleaf_free(btree, leaf) < 16) {
			mark_buffer_dirty(cursor_leafbuf(cursor));
			struct buffer_head *newbuf = new_leaf(btree);
			if (!newbuf) {
				segs = -ENOMEM;
				goto out_create;
			}
			/*
			 * ENOSPC on btree index split could leave the cache state
			 * badly messed up.  Going to have to do this in two steps:
			 * first, look at the cursor to see how many splits we need,
			 * then make sure we have that, or give up before starting.
			 */
			btree_insert_leaf(cursor, index, newbuf);
			leaf = bufdata(cursor_leafbuf(cursor));
			dwalk_probe(leaf, sb->blocksize, &headwalk, index);
		}
		if (i < 0) {
			trace("emit below");
			dwalk_add(&headwalk, index - below, make_extent(map[0].block - below, below));
			continue;
		}
		if (i == segs) {
			trace("emit above");
			dwalk_add(&headwalk, index, make_extent(map[segs - 1].block + map[segs - 1].count, above));
			continue;
		}
		trace("pack 0x%Lx => %Lx/%x", (L)index, (L)map[i].block, map[i].count);
		dleaf_dump(btree, leaf);
		dwalk_add(&headwalk, index, make_extent(map[i].block, map[i].count));
		dleaf_dump(btree, leaf);
		index += map[i].count;
	}
	if (tail) {
		if (dleaf_need(btree, tail) < dleaf_free(btree, leaf))
			dleaf_merge(btree, leaf, tail);
		else {
			mark_buffer_dirty(cursor_leafbuf(cursor));
			assert(dleaf_groups(tail) >= 1);
			/* Tail does not fit, add it as a new btree leaf */
			struct buffer_head *newbuf = new_leaf(btree);
			if (!newbuf) {
				segs = -ENOMEM;
				goto out_create;
			}
			memcpy(bufdata(newbuf), tail, sb->blocksize);
			if ((err = btree_insert_leaf(cursor, tailkey, newbuf))) {
				free(tail);
				segs = err;
				goto out_unlock;
			}
		}
	}
	mark_buffer_dirty(cursor_leafbuf(cursor));
out_create:
	if (tail)
		free(tail);
out_release:
	release_cursor(cursor);
out_unlock:
	if (create)
		up_write(&cursor->btree->lock);
	else
		up_read(&cursor->btree->lock);
	free_cursor(cursor);
	return segs;
}

#ifdef __KERNEL__
#include <linux/mpage.h>

int tux3_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create)
{
	trace("==> inum %Lu, iblock %Lu, b_size %zu, create %d",
	      (L)tux_inode(inode)->inum, (L)iblock, bh_result->b_size, create);

	struct sb *sb = tux_sb(inode->i_sb);
	size_t max_blocks = bh_result->b_size >> inode->i_blkbits;
	struct btree *btree = &tux_inode(inode)->btree;
	if (!btree->root.depth) {
		assert(create && sb->logmap == inode);
		return 0;
	}

	struct seg seg;
	int segs = map_region(inode, iblock, max_blocks, &seg, 1, create);
	if (segs < 0) {
		warn("map_region failed: %d", -segs);
		return -EIO;
	}
	assert(segs == 1);
	size_t blocks = min_t(size_t, max_blocks, seg.count);
	if (seg.state == SEG_NEW) {
		assert(seg.block);
		set_buffer_new(bh_result);
		inode->i_blocks += blocks << (sb->blockbits - 9);
	}
	if (seg.state != SEG_HOLE) {
		map_bh(bh_result, inode->i_sb, seg.block);
		bh_result->b_size = blocks << sb->blockbits;
	}
	trace("<== inum %Lu, mapped %d, block %Lu, size %zu",
	      (L)tux_inode(inode)->inum, buffer_mapped(bh_result),
	      (L)bh_result->b_blocknr, bh_result->b_size);

	return 0;
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
	if (page && PageUptodate(page)) {
		spin_lock(&mapping->private_lock);
		if (page_has_buffers(page)) {
			bh = find_get_buffer(page, offset);
			assert(buffer_uptodate(bh));
		}
		spin_unlock(&mapping->private_lock);
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
	offset = iblock & ((PAGE_CACHE_SHIFT - inode->i_blkbits) - 1);

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

	index = iblock >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	offset = iblock & ((PAGE_CACHE_SHIFT - inode->i_blkbits) - 1);

	err = mapping->a_ops->write_begin(NULL, mapping,
					  iblock << inode->i_blkbits,
					  1 << inode->i_blkbits,
					  AOP_FLAG_UNINTERRUPTIBLE,
					  &page, &fsdata);
	if (err)
		return NULL;

	assert(page_has_buffers(page));

	bh = page_buffers(page);
	while (offset--)
		bh = bh->b_this_page;
	get_bh(bh);
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

static int tux3_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	*pagep = NULL;
	return block_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				 tux3_get_block);
}

static int tux3_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, tux3_get_block, wbc);
}

static int tux3_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, tux3_get_block);
}

static ssize_t tux3_direct_IO(int rw, struct kiocb *iocb,
			      const struct iovec *iov,
			      loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	return blockdev_direct_IO(rw, iocb, inode, inode->i_sb->s_bdev, iov,
				  offset, nr_segs, tux3_get_block, NULL);
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
	.writepages		= tux3_writepages,
	.sync_page		= block_sync_page,
	.write_begin		= tux3_write_begin,
	.write_end		= generic_write_end,
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
	.writepages	= tux3_writepages,
	.sync_page	= block_sync_page,
	.write_begin	= tux3_write_begin,
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
#if 1
	return block_write_full_page(page, tux3_vol_get_block, wbc);
#else
	/* This shouldn't be called */
	BUG_ON(1);
	return 0;
#endif
}

static int tux3_vol_write_begin(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	*pagep = NULL;
	return block_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				 tux3_vol_get_block);
}

const struct address_space_operations tux_vol_aops = {
	.readpage	= tux3_vol_readpage,
	.writepage	= tux3_vol_writepage,
	.sync_page	= block_sync_page,
	.write_begin	= tux3_vol_write_begin,
};
#endif /* __KERNEL__ */
