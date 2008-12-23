#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/aio.h>
#endif
#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

static void dwalk_seek(struct dwalk *walk, tuxkey_t key)
{
	/* dwalk_probe should just return a flag */
	if (!dwalk_end(walk)) {
		/* dwalk_probe should just return a flag */
		do {
			if (dwalk_index(walk) + dwalk_count(walk) > key)
				break;
		} while (dwalk_next(walk));
	}
}

struct seg { block_t block; int count; };

/* userland only */
void show_segs(struct seg seglist[], unsigned segs)
{
	printf("%i segs: ", segs);
	for (int i = 0; i < segs; i++)
		printf("%Lx/%i ", (L)seglist[i].block, seglist[i].count);
	printf("\n");
}

static int find_segs(struct cursor *cursor, block_t start, unsigned limit,
	struct seg seg[], unsigned max_segs, struct dwalk seek[2], unsigned overlap[2])
{
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

	/* Probe below io start to include overlapping extents */
	dwalk_probe(leaf, sb->blocksize, walk, 0); // start at beginning of leaf just for now
	dwalk_seek(walk, start);
	seek[0] = *walk;
	struct diskextent *next_extent = NULL;
	block_t index = start, next_index = 0;
	unsigned segs = 0, below = 0, above = 0, next_count = 0;
	while (index < limit && segs < max_segs) {
		trace("index %Lx, limit %Lx", (L)index, (L)limit);
		if (next_extent) {
			trace("emit %Lx/%x", (L)extent_block(*next_extent), next_count);
			assert(next_index >= start);
			seg[segs++] = (struct seg){ extent_block(*next_extent), next_count };
			index += next_count;
			next_extent = NULL;
			continue;
		}

		if (dwalk_end(walk))
			next_index = limit;
		else {
			next_extent = walk->extent;
			next_index = dwalk_index(walk);
			next_count = dwalk_count(walk);
			dwalk_next(walk);
			trace("next_index = %Lx, next_count = %x", (L)next_index, next_count);
			if (next_index < start) {
				below = start - next_index;
				next_index = start;
			} else if (next_index >= limit) {
				next_extent = NULL;
				dwalk_back(walk);
			} else if (next_index + next_count > limit) {
				above = next_index + next_count - limit;
				next_count = limit - next_index;
			}
		}

		if (index < next_index) {
			int gap = next_index - index;
			trace("index = %Lx, next = %Lx, gap = %i", (L)index, (L)next_index, gap);
			if (index + gap > limit)
				gap = limit - index;
			trace("emit gap %x", gap);
			seg[segs++] = (struct seg){ .count = -gap };
			index += gap;
		}
	}
	trace("\n");
	trace("below = %i, above = %i", below, above);
	seek[1] = *walk;
	if (segs) {
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

static int fill_segs(struct cursor *cursor, block_t start, unsigned limit,
	struct seg seg[], unsigned segs, struct dwalk seek[2], unsigned overlap[2])
{
	struct btree *btree = cursor->btree;
	struct sb *sb = btree->sb;
	struct dleaf *leaf = bufdata(cursor_leafbuf(cursor));
	struct dleaf *tail = malloc(sb->blocksize); // error???
	tuxkey_t tailkey;
	int err;

	dleaf_init(btree, tail);
	if (!dwalk_end(&seek[1])) {
		tailkey = dwalk_index(&seek[1]);
		trace("leaf..."); dleaf_dump(btree, leaf);
		err = dleaf_split_at(leaf, tail, seek[1].entry, sb->blocksize);
		trace("leaf..."); dleaf_dump(btree, leaf);
		trace("tail..."); dleaf_dump(btree, tail);
	}

	for (int i = 0; i < segs; i++) {
		int count = seg[i].count;
		if (count < 0) {
			count = -count;
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
			seg[i] = (struct seg){ block, count };
		}
	}
	/* Go back to region start and pack in new segs */
	dleaf_dump(btree, leaf);
	dwalk_chop(seek);
	dleaf_dump(btree, leaf);
	for (int i = 0, index = start; i < segs; i++) {
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
			insert_node(btree, dwalk_index(seek), bufindex(newbuf), cursor);
			leaf = bufdata(cursor_leafbuf(cursor));
			dwalk_probe(leaf, sb->blocksize, seek, 0);
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

static int get_segs(struct inode *inode, block_t start, unsigned limit, struct seg segvec[], unsigned max_segs, int create)
{
	struct cursor *cursor = alloc_cursor(&tux_inode(inode)->btree, 1); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;

	unsigned overlap[2];
	struct dwalk seek[2] = { };
	int segs = find_segs(cursor, start, limit, segvec, max_segs, seek, overlap);
	if (segs > 0 && create)
		segs = fill_segs(cursor, start, limit, segvec, segs, seek, overlap);
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

	int segs = get_segs(inode, start, limit, segvec, 1, write);
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
		int count = segvec[i].count, hole = count < 0;
		if (hole)
			count = -count;
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
	int segs = get_segs(inode, iblock, iblock + max_blocks, &seg, 1, create);
	if (segs < 0) {
		warn("get_segs failed: %d", -segs);
		return -EIO;
	}
	if (seg.count < 0)
		set_buffer_uptodate(bh_result);
	else {
		size_t blocks = min_t(size_t, max_blocks, seg.count);
		map_bh(bh_result, inode->i_sb, seg.block);
		bh_result->b_size = blocks << sb->blockbits;
		inode->i_blocks += blocks << (sb->blockbits - 9);
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
