#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/aio.h>
#endif
#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

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
	int depth = tux_inode(inode)->btree.root.depth, try = 0, i, err;
	if (!depth) {
		if (!write) {
			trace("unmapped block %Lx", (L)bufindex(buffer));
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_uptodate(buffer);
			return 0;
		}
		return -EIO;
	}
	if (write && buffer_empty(buffer))
		warn("egad, writing an invalid buffer");
	if (!write && buffer_dirty(buffer))
		warn("egad, reading a dirty buffer");

	block_t start, limit;
	guess_extent(buffer, &start, &limit, write);
	printf("---- extent 0x%Lx/%Lx ----\n", (L)start, (L)limit - start);
	struct extent seg[1000];
	struct cursor *cursor = alloc_cursor(depth + 1);
	if (!cursor)
		return -ENOMEM;

	if ((err = probe(&tux_inode(inode)->btree, start, cursor))) {
		free_cursor(cursor);
		return err;
	}
retry:
	//assert(start >= this_key(cursor, depth))
	/* do not overlap next leaf */
	if (limit > next_key(cursor, depth))
		limit = next_key(cursor, depth);
	unsigned segs = 0;
	struct dleaf *leaf = bufdata(cursor[depth].buffer);
	struct dwalk *walk = &(struct dwalk){ };
dleaf_dump(&tux_inode(inode)->btree, leaf);
	/* Probe below io start to include overlapping extents */
	dwalk_probe(leaf, sb->blocksize, walk, 0); // start at beginning of leaf just for now

	/* skip extents below start */
	for (struct extent *extent; (extent = dwalk_next(walk));)
		if (dwalk_index(walk) + extent_count(*extent) > start) {
			if (dwalk_index(walk) <= start)
				dwalk_back(walk);
			break;
		}
	struct dwalk rewind = *walk;
	printf("prior extents:");
	for (struct extent *extent; (extent = dwalk_next(walk));)
		printf(" 0x%Lx => %Lx/%x;", (L)dwalk_index(walk), (L)extent_block(*extent), extent_count(*extent));
	printf("\n");

	if (dleaf_groups(leaf))
		printf("---- rewind to 0x%Lx => %Lx/%x ----\n", (L)dwalk_index(&rewind), (L)extent_block(*rewind.extent), extent_count(*rewind.extent));
	*walk = rewind;

	struct extent *next_extent = NULL;
	block_t index = start, offset = 0;
	while (index < limit) {
		trace("index %Lx, limit %Lx", (L)index, (L)limit);
		if (next_extent) {
			trace("emit %Lx/%x", (L)extent_block(*next_extent), extent_count(*next_extent));
			seg[segs++] = *next_extent;

			unsigned count = extent_count(*next_extent);
			if (start > dwalk_index(walk))
				count -= start - dwalk_index(walk);
			index += count;
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
			block_t block = 0;
			if (write) {
				block = balloc_extent(sb, gap); // goal ???
				if (block == -1)
					goto nospace; // clean up !!!
			}
			seg[segs++] = make_extent(block, gap);
			index += gap;
		}
	}

	if (write) {
		while (next_extent) {
			trace("save tail");
			seg[segs++] = *next_extent;
			next_extent = dwalk_next(walk);
		}
	}

	printf("segs (offset = %Lx):", (L)offset);
	for (i = 0, index = start; i < segs; i++) {
		printf(" %Lx => %Lx/%x;", (L)index - offset, (L)extent_block(seg[i]), extent_count(seg[i]));
		index += extent_count(seg[i]);
	}
	printf(" (%i)\n", segs);

	if (write) {
		*walk = rewind;
		for (i = 0, index = start - offset; i < segs; i++, index += extent_count(seg[i]))
			dwalk_mock(walk, index, make_extent(extent_block(seg[i]), extent_count(seg[i])));
		trace("need %i data and %i index bytes", walk->mock.free, -walk->mock.used);
		trace("need %i bytes, %u bytes free", walk->mock.free - walk->mock.used, dleaf_free(&tux_inode(inode)->btree, leaf));
		if (dleaf_free(&tux_inode(inode)->btree, leaf) <= walk->mock.free - walk->mock.used) {
			trace_on("--------- split leaf ---------");
			assert(!try);
			if ((err = btree_leaf_split(&tux_inode(inode)->btree, cursor, 0)))
				goto eek;
			try = 1;
			goto retry;
		}

		*walk = rewind;
		if (dleaf_groups(leaf))
			dwalk_chop_after(walk);
		for (i = 0, index = start - offset; i < segs; i++) {
			trace("pack 0x%Lx => %Lx/%x", (L)index, (L)extent_block(seg[i]), extent_count(seg[i]));
			dwalk_pack(walk, index, make_extent(extent_block(seg[i]), extent_count(seg[i])));
			index += extent_count(seg[i]);
		}
		mark_buffer_dirty(cursor[tux_inode(inode)->btree.root.depth].buffer);

		//dleaf_dump(&tux_inode(inode)->btree, leaf);
		/* assert we used exactly the expected space */
		/* assert(??? == ???); */
		/* check leaf */
		if (0)
			goto eek;
	}

	unsigned skip = offset;
	for (i = 0, index = start - offset; !err && index < limit; i++) {
		unsigned count = extent_count(seg[i]);
		trace_on("extent 0x%Lx/%x => %Lx", (L)index, count, (L)extent_block(seg[i]));
		for (int j = skip; !err && j < count; j++) {
			block_t block = extent_block(seg[i]) + j;
			buffer = blockget(mapping(inode), index + j);
			trace_on("block 0x%Lx => %Lx", (L)bufindex(buffer), (L)block);
			if (write) {
				err = diskwrite(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			} else {
				if (!block) { /* block zero is never allocated */
					trace("zero fill buffer");
					memset(bufdata(buffer), 0, sb->blocksize);
					continue;
				}
				err = diskread(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			}
			brelse(set_buffer_uptodate(buffer)); // leave empty if error ???
		}
		index += count;
		skip = 0;
	}
	release_cursor(cursor, depth + 1);
	free_cursor(cursor);
	return err;
nospace:
	err = -ENOSPC;
eek:
	warn("could not add extent to tree: %d", err);
	/* release_cursor() was already called at error point */
	free_cursor(cursor);
	// free blocks and try to clean up ???
	return -EIO;
}
#else /* __KERNEL__ */
int tux3_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create)
{
	int blocksize = 1 << inode->i_blkbits;
	sector_t last_iblock;

	last_iblock = (i_size_read(inode) + (blocksize - 1))
		>> inode->i_blkbits;
	if (iblock >= last_iblock)
		return -EIO;

	struct sb *sbi = tux_sb(inode->i_sb);
	size_t max_blocks = bh_result->b_size >> inode->i_blkbits;
	int depth = tux_inode(inode)->btree.root.depth, err;
	if (!depth) {
		trace("unmapped block %Lx", (L)iblock);
		return 0;
	}

	block_t start = iblock, limit = iblock + max_blocks;
	struct extent seg[10];
	struct cursor *cursor = alloc_cursor(depth + 1);
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
	unsigned segs = 0;
	struct dleaf *leaf = bufdata(cursor[depth].buffer);
	struct dwalk *walk = &(struct dwalk){ };
	dleaf_dump(&tux_inode(inode)->btree, leaf);
	/* Probe below io start to include overlapping extents */
	dwalk_probe(leaf, sbi->blocksize, walk, 0); // start at beginning of leaf just for now

	/* skip extents below start */
	for (struct extent *extent; (extent = dwalk_next(walk));)
		if (dwalk_index(walk) + extent_count(*extent) > start) {
			if (dwalk_index(walk) <= start)
				dwalk_back(walk);
			break;
		}

	struct extent *next_extent = NULL;
	block_t index = start, offset = 0;
	while (index < limit && segs < ARRAY_SIZE(seg)) {
		trace("index %Lx, limit %Lx", (L)index, (L)limit);
		if (next_extent) {
			trace("emit %Lx/%x", (L)extent_block(*next_extent), extent_count(*next_extent));
			seg[segs++] = *next_extent;

			unsigned count = extent_count(*next_extent);
			if (start > dwalk_index(walk))
				count -= start - dwalk_index(walk);
			index += count;
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
			/* there is gap (hole), so stop */
			break;
		}
	}

	block_t block = extent_block(seg[0]) + offset;
	size_t count = extent_count(seg[0]) - offset;
	for (int i = 1; i < segs; i++) {
		if (block + count != extent_block(seg[i]))
			break;
		count += extent_count(seg[i]);
	}
	if (block) {
		map_bh(bh_result, inode->i_sb, block);
		bh_result->b_size = min(max_blocks, count) << sbi->blockbits;
	}
	trace("%s: block %Lu, size %zu", __func__,
	      (L)bh_result->b_blocknr, bh_result->b_size);

	release_cursor(cursor, depth + 1);
	free_cursor(cursor);

	return err;
}

struct buffer_head *blockread(struct address_space *mapping, block_t iblock)
{
	struct inode *inode = mapping->host;
	pgoff_t index;
	struct page *page;
	struct buffer_head *bh;
	int offset;

	printk("%s: ==> ino %Lu, block %Lu\n", __func__, tux_inode(inode)->inum, iblock);

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

	printk("%s: <=== b_blocknr %Lu\n", __func__, (L)bh->b_blocknr);

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
	int offset;

	printk("%s: ino %Lu, block %Lu\n", __func__, tux_inode(inode)->inum, iblock);

	index = iblock >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	offset = iblock & ((PAGE_CACHE_SHIFT - inode->i_blkbits) - 1);

	page = grab_cache_page(mapping, index);
	if (!page)
		return NULL;

	if (!page_has_buffers(page))
		create_empty_buffers(page, tux_sb(inode->i_sb)->blocksize, 0);

	bh = page_buffers(page);
	while (offset--)
		bh = bh->b_this_page;
	get_bh(bh);

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
	.bmap		= tux3_bmap,
};
#endif /* __KERNEL__ */
