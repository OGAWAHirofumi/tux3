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
	for (struct diskextent *extent; (extent = dwalk_next(walk));)
		if (dwalk_index(walk) + extent_count(*extent) > key) {
			if (dwalk_index(walk) <= key)
				dwalk_back(walk);
			break;
		}
}

struct seg { block_t block; int count; };

int get_segs(struct inode *inode, block_t start, unsigned limit, struct seg seg[], unsigned max_segs, int write)
{
	struct sb *sbi = tux_sb(inode->i_sb);
	int depth = tux_inode(inode)->btree.root.depth, i, err;
	if (!depth)
		return 0;

	struct cursor *cursor = alloc_cursor(depth + 2); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;

	if ((err = probe(&tux_inode(inode)->btree, start, cursor))) {
		free_cursor(cursor);
		return err;
	}
	//assert(start >= this_key(cursor, depth))
	/* do not overlap next leaf */
	if (limit > next_key(cursor, depth))
		limit = next_key(cursor, depth);
	struct dleaf *leaf = bufdata(cursor_leafbuf(cursor));
	struct dwalk *walk = &(struct dwalk){ };
	dleaf_dump(&tux_inode(inode)->btree, leaf);
	/* Probe below io start to include overlapping extents */
	dwalk_probe(leaf, sbi->blocksize, walk, 0); // start at beginning of leaf just for now
	dwalk_seek(walk, start);
	struct dwalk rewind = *walk;
	struct diskextent *next_extent = NULL;
	block_t index = start, offset = 0;
	unsigned segs = 0, update_dtree = 0;
	while (index < limit && segs < max_segs) {
		trace("index %Lx, limit %Lx", (L)index, (L)limit);
		if (next_extent) {
			trace("emit %Lx/%x", (L)extent_block(*next_extent), extent_count(*next_extent));
			seg[segs++] = (struct seg){ extent_block(*next_extent), extent_count(*next_extent) };

			unsigned count = extent_count(*next_extent);
			if (start > dwalk_index(walk))
				count -= start - dwalk_index(walk);
			index += count;

			next_extent = NULL;
			continue;
		}

		block_t next_index = limit;
		if ((next_extent = dwalk_next(walk))) {
			next_index = dwalk_index(walk);
			trace("next_index = %Lx", (L)next_index);
			if (next_index < start) {
				offset = start - next_index;
				next_index = start;
			}
		}
		if (index < next_index) {
			int gap = next_index - index;
			trace("index = %Lx, offset = %Li, next = %Lx, gap = %i", (L)index, (L)offset, (L)next_index, gap);
			if (index + gap > limit)
				gap = limit - index;
			trace("fill gap at %Lx/%x", (L)index, gap);

			if (!write) {
				seg[segs++] = (struct seg){ .count = -gap };
				continue;
			}

			block_t block = balloc_extent(sbi, gap); // goal ???
			if (block == -1) {
				segs = -ENOSPC;
				goto nospace;
			}
			seg[segs++] = (struct seg){ block, gap };
			update_dtree = 1;
		}
	}

	if (update_dtree) {
		/* Update dtree by new extents */
		*walk = rewind;
		for (int try = 0; try < 2; try++) {
			/* Everything fits in the leaf? */
			for (i = 0, index = start - offset; i < segs; i++, index += seg[i].count)
				dwalk_mock(walk, index, make_extent(seg[i].block, seg[i].count));
			trace("need %i data and %i index bytes", walk->mock.free, -walk->mock.used);
			trace("need %i bytes, %u bytes free", walk->mock.free - walk->mock.used, dleaf_free(&tux_inode(inode)->btree, leaf));
			if (dleaf_free(&tux_inode(inode)->btree, leaf) >= walk->mock.free - walk->mock.used)
				break;
			if (try)
				goto eek;
			trace_on("--------- split leaf ---------");
			if ((err = btree_leaf_split(&tux_inode(inode)->btree, cursor, start))) {
				segs = err;
				goto eek;
			}
			depth = tux_inode(inode)->btree.root.depth;
			dwalk_probe(leaf, sbi->blocksize, walk, 0);
			dwalk_seek(walk, start);
			rewind = *walk;
		}

		*walk = rewind;
		if (dleaf_groups(leaf))
			dwalk_chop_after(walk);
		for (i = 0, index = start - offset; i < segs; i++) {
			trace("pack 0x%Lx => %Lx/%x", (L)index, (L)seg[i].block, seg[i].count);
			dwalk_pack(walk, index, make_extent(seg[i].block, seg[i].count));
			index += seg[i].count;
		}
		mark_buffer_dirty(cursor_leafbuf(cursor));
	}
	seg[0].block += offset;
	seg[0].count -= offset;
eek:
	// free blocks and try to clean up ???
	release_cursor(cursor);
nospace:
	/* release_cursor() was already called at error point */
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

	struct seg seg[10];
	int segs = get_segs(inode, start, limit, seg, ARRAY_SIZE(seg), write);
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
		int count = seg[i].count, hole = count < 0;
		if (hole)
			count = -count;
		trace_on("extent 0x%Lx/%x => %Lx", (L)index, count, (L)seg[i].block);
		for (int j = 0; !err && j < count; j++) {
			block_t block = seg[i].block + j;
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
		   struct buffer_head *bh_result, int write)
{
	trace("==> inum %Lu, iblock %Lu, b_size %zu, write %d",
	      (L)tux_inode(inode)->inum, (L)iblock, bh_result->b_size, write);

	struct sb *sbi = tux_sb(inode->i_sb);
	size_t max_blocks = bh_result->b_size >> inode->i_blkbits;
	int depth = tux_inode(inode)->btree.root.depth;
	if (!depth) {
		warn("Uninitialied inode %lx", inode->i_ino);
		return 0;
	}

	struct seg seg;
	int segs = get_segs(inode, iblock, iblock + max_blocks, &seg, 1, write);
	if (segs < 0) {
		warn("get_segs failed: %d", -segs);
		return -EIO;
	}
	if (seg.count < 0)
		set_buffer_uptodate(bh_result);
	else {
		unsigned blocks = min(max_blocks, (unsigned)seg.count);
		map_bh(bh_result, inode->i_sb, seg.block);
		bh_result->b_size = blocks << sbi->blockbits;
		inode->i_blocks += blocks << (sbi->blockbits - 9);
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
