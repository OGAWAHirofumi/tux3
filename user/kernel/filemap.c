#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/aio.h>
#endif
#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

#define SEG_HOLE	(1 << 0)
#define SEG_NEW	(1 << 1)

struct seg { block_t block; unsigned count; unsigned state; };

/* userland only */
void show_segs(struct seg seglist[], unsigned segs)
{
	printf("%i segs: ", segs);
	for (int i = 0; i < segs; i++)
		printf("%Lx/%i ", (L)seglist[i].block, seglist[i].count);
	printf("\n");
}

static int find_segs(struct cursor *cursor, block_t start, block_t limit,
	struct seg seg[], unsigned max_segs, struct dwalk seek[2], unsigned overlap[2])
{
	assert(max_segs > 0);
	trace("--- index %Lx, limit %Lx ---", (L)start, (L)limit);
	struct btree *btree = cursor->btree;
	struct sb *sb = btree->sb;
	int err;
	if (!btree->root.depth)
		return 0;

	if ((err = probe(btree, start, cursor))) {
		free_cursor(cursor);
		return err;
	}
	//assert(start >= this_key(cursor, btree->root.depth))
	/* do not overlap next leaf */
	if (limit > next_key(cursor, btree->root.depth))
		limit = next_key(cursor, btree->root.depth);
	struct dleaf *leaf = bufdata(cursor_leafbuf(cursor));
	dleaf_dump(btree, leaf);

	struct dwalk *walk = &(struct dwalk){ };
	block_t index = start, seg_start;
	unsigned segs = 0;
	dwalk_probe(leaf, sb->blocksize, walk, start);
	seek[0] = *walk;
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
			block_t gap = ex_index - index;
			index = ex_index;
			seg[segs++] = (struct seg){ .count = gap, .state = SEG_HOLE };
		} else {
			block_t block = dwalk_block(walk);
			unsigned count = dwalk_count(walk);
			trace("emit %Lx/%x", (L)block, count );
			seg[segs++] = (struct seg){ .block = block, .count = count };
			index = ex_index + count;
			dwalk_next(walk);
 		}
	}
	trace("\n");
	seek[1] = *walk;
	if (segs) {
		block_t below = start - seg_start;
		block_t above = index - min(index, limit);
		seg[0].block += below;
		seg[0].count -= below;
		seg[segs - 1].count -= above;
		if (overlap) {
			overlap[0] = below;
			overlap[1] = above;
		}
	}
	return segs;
}

/*
 * This interface has no way of telling how long the seg vector is in case segs
 * has to be increased.  If ENOSPC, has no way of telling how may segs were
 * successfully allocated and recorded in the btree.  Sucks, still.
 */

static int fill_segs(struct cursor *cursor, block_t start, block_t limit,
	struct seg seg[], int segs, struct dwalk seek[2], unsigned overlap[2])
{
	struct btree *btree = cursor->btree;
	struct sb *sb = btree->sb;
	struct dleaf *leaf = bufdata(cursor_leafbuf(cursor));
	struct dleaf *tail = malloc(sb->blocksize); // error???
	unsigned below = overlap[0], above = overlap[1];
	tuxkey_t tailkey;

	dleaf_init(btree, tail);
	if (!dwalk_end(&seek[1])) {
		tailkey = dwalk_index(&seek[1]);
		trace("leaf..."); dleaf_dump(btree, leaf);
		dwalk_copy(&seek[1], tail);
		trace("leaf..."); dleaf_dump(btree, leaf);
		trace("tail..."); dleaf_dump(btree, tail);
	}

	for (int i = 0; i < segs; i++) {
		if (seg[i].state == SEG_HOLE) {
			unsigned count = seg[i].count;
			block_t block = balloc(sb, count); // goal ???
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
				return -ENOSPC;
			}
			seg[i] = (struct seg){ .block = block, .count = count, .state = SEG_NEW, };
		}
	}
	/* Go back to region start and pack in new segs */
	dleaf_dump(btree, leaf);
	dwalk_chop(seek);
	dleaf_dump(btree, leaf);
	for (int i = -!!below, index = start; i < segs + !!above; i++) {
		if (dleaf_free(btree, leaf) < 16) {
			struct buffer_head *newbuf = new_leaf(btree);
			if (!newbuf) {
				release_cursor(cursor);
				return -ENOMEM;
			}
			level_pop_brelse_dirty(cursor);
			level_push(cursor, newbuf, NULL);
			/*
			 * ENOSPC on btree index split could leave the cache state
			 * badly messed up.  Going to have to do this in two steps:
			 * first, look at the cursor to see how many splits we need,
			 * then make sure we have that, or give up before starting.
			 */
			insert_node(btree, index, bufindex(newbuf), cursor);
			leaf = bufdata(cursor_leafbuf(cursor));
			dwalk_probe(leaf, sb->blocksize, seek, index);
		}
		if (i < 0) {
			trace("emit below");
			dwalk_add(seek, index - below, make_extent(seg[0].block - below, below));
			continue;
		}
		if (i == segs) {
			trace("emit above");
			dwalk_add(seek, index, make_extent(seg[segs - 1].block + seg[segs - 1].count, above));
			continue;
		}
		trace("pack 0x%Lx => %Lx/%x", (L)index, (L)seg[i].block, seg[i].count);
		dleaf_dump(btree, leaf);
		dwalk_add(seek, index, make_extent(seg[i].block, seg[i].count));
		dleaf_dump(btree, leaf);
		index += seg[i].count;
	}
	if (dleaf_need(btree, tail) < dleaf_free(btree, leaf)) {
		trace("Merge tail");
		dleaf_dump(btree, leaf);
		dleaf_merge(btree, leaf, tail);
		dleaf_dump(btree, leaf);
	} else {
		assert(dleaf_groups(tail) >= 1);
		/* Tail does not fit, add it as a new btree leaf */
		struct buffer_head *newbuf = new_leaf(btree);
		if (!newbuf) {
			release_cursor(cursor);
			return -ENOMEM;
		}
		memcpy(bufdata(newbuf), tail, sb->blocksize);
		level_pop_brelse_dirty(cursor);
		level_push(cursor, newbuf, NULL);
		insert_node(btree, tailkey, bufindex(newbuf), cursor);
	}
	free(tail);
	mark_buffer_dirty(cursor_leafbuf(cursor));
printf("\n");
show_tree(btree);
//eek:
	release_cursor(cursor);
	return segs;
}

static int get_segs(struct inode *inode, block_t start, block_t count, struct seg segvec[], unsigned max_segs, int create)
{
	struct cursor *cursor = alloc_cursor(&tux_inode(inode)->btree, 1); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;

	unsigned overlap[2];
	struct dwalk seek[2] = { };
	int segs = find_segs(cursor, start, start + count, segvec, max_segs, seek, overlap);
	if (segs > 0 && create)
		segs = fill_segs(cursor, start, start + count, segvec, segs, seek, overlap);
	if (segs >= 0)
		release_cursor(cursor);
	free_cursor(cursor);
	return segs;
}

#ifndef __KERNEL__
/*
 * Extrapolate from single buffer flush or blockread to opportunistic exent IO
 *
 * For write, try to include adjoining buffers above and below:
 *  - stop at first uncached or clean buffer in either direction
 *
 * For read (essentially readahead):
 *  - stop at first present buffer
 *  - stop at end of file
 *
 * For both, stop when extent is "big enough", whatever that means.
 */
void guess_extent(struct buffer_head *buffer, block_t *start, block_t *limit, int write)
{
	struct inode *inode = buffer_inode(buffer);
	block_t ends[2] = { bufindex(buffer), bufindex(buffer) };
	for (int up = !write; up < 2; up++) {
		while (ends[1] - ends[0] + 1 < MAX_EXTENT) {
			block_t next = ends[up] + (up ? 1 : -1);
			struct buffer_head *nextbuf = peekblk(buffer->map, next);
			if (!nextbuf) {
				if (write)
					break;
				if (next > inode->i_size >> tux_sb(inode->i_sb)->blockbits)
					break;
			} else {
				unsigned stop = write ? !buffer_dirty(nextbuf) : buffer_empty(nextbuf);
				brelse(nextbuf);
				if (stop)
					break;
			}
			ends[up] = next; /* what happens to the beer you send */
		}
	}
	*start = ends[0];
	*limit = ends[1] + 1;
}

int filemap_extent_io(struct buffer_head *buffer, int write)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);
	trace("%s inode 0x%Lx block 0x%Lx", write ? "write" : "read", (L)tux_inode(inode)->inum, (L)bufindex(buffer));
	if (bufindex(buffer) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	struct dev *dev = sb->devmap->dev;
	assert(dev->bits >= 8 && dev->fd);
	if (write && buffer_empty(buffer))
		warn("egad, writing an invalid buffer");
	if (!write && buffer_dirty(buffer))
		warn("egad, reading a dirty buffer");

	block_t start, limit;
	guess_extent(buffer, &start, &limit, write);
	printf("---- extent 0x%Lx/%Lx ----\n", (L)start, (L)limit - start);

	struct seg segvec[10];

	int segs = get_segs(inode, start, limit - start, segvec, 1, write);
	if (segs < 0)
		return segs;

	if (!segs) {
		if (!write) {
			trace("unmapped block %Lx", (L)bufindex(buffer));
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_uptodate(buffer);
			return 0;
		}
		return -EIO;
	}

	int err = 0;
	for (int i = 0, index = start; !err && index < limit; i++) {
		int count = segvec[i].count, hole = segvec[i].state == SEG_HOLE;
		trace_on("extent 0x%Lx/%x => %Lx", (L)index, count, (L)segvec[i].block);
		for (int j = 0; !err && j < count; j++) {
			block_t block = segvec[i].block + j;
			buffer = blockget(mapping(inode), index + j);
			trace_on("block 0x%Lx => %Lx", (L)bufindex(buffer), (L)block);
			if (write) {
				err = diskwrite(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			} else {
				if (hole) {
					trace("zero fill buffer");
					memset(bufdata(buffer), 0, sb->blocksize);
					continue;
				}
				err = diskread(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			}
			brelse(set_buffer_uptodate(buffer)); // leave empty if error ???
		}
		index += count;
	}
	return err;
}
#else /* __KERNEL__ */
int tux3_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create)
{
	trace("==> inum %Lu, iblock %Lu, b_size %zu, create %d",
	      (L)tux_inode(inode)->inum, (L)iblock, bh_result->b_size, create);

	struct sb *sb = tux_sb(inode->i_sb);
	size_t max_blocks = bh_result->b_size >> inode->i_blkbits;
	struct btree *btree = &tux_inode(inode)->btree;
	int depth = btree->root.depth;
	if (!depth) {
		warn("Uninitialied inode %lx", inode->i_ino);
		return 0;
	}

	struct seg seg;
	int segs = get_segs(inode, iblock, max_blocks, &seg, 1, create);
	if (segs < 0) {
		warn("get_segs failed: %d", -segs);
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

struct buffer_head *blockread(struct address_space *mapping, block_t iblock)
{
	struct inode *inode = mapping->host;
	pgoff_t index;
	struct page *page;
	struct buffer_head *bh;
	int offset;

	index = iblock >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	offset = iblock & ((PAGE_CACHE_SHIFT - inode->i_blkbits) - 1);

	page = read_mapping_page(mapping, index, NULL);
	if (IS_ERR(page))
		goto error;
	if (PageError(page))
		goto error_page;

	lock_page(page);

	if (!page_has_buffers(page))
		create_empty_buffers(page, tux_sb(inode->i_sb)->blocksize, 0);

	bh = page_buffers(page);
	while (offset--)
		bh = bh->b_this_page;
	get_bh(bh);

	unlock_page(page);
	page_cache_release(page);

	return bh;

error_page:
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

	if (!page_has_buffers(page))
		create_empty_buffers(page, tux_sb(inode->i_sb)->blocksize, 0);

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
#endif /* __KERNEL__ */
