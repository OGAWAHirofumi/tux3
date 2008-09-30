#ifndef trace
#define trace trace_on
#endif

#define main notmain0
#include "balloc.c"
#undef main

#define main notmain1
#include "dleaf.c"
#undef main

#define main notmain3
#include "dir.c"
#undef main

#define main notmain2
#include "xattr.c"
#undef main

#define iattr_notmain_from_inode
#define main iattr_notmain_from_inode
#include "ileaf.c"
#undef main

#define main notmain4
#include "btree.c"
#undef main

int filemap_blockread(struct buffer *buffer)
{
	struct inode *inode = buffer->map->inode;
	struct sb *sb = inode->sb;
	warn("block read <%Lx:%Lx>", (L)inode->inum, (L)buffer->index);
	if (buffer->index & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels)
		goto hole;
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	unsigned count = 0;
	struct extent *found = dleaf_lookup(&inode->btree, path[levels].buffer->data, buffer->index, &count);
	//dleaf_dump(&inode->btree, path[levels].buffer->data);

	release_path(path, levels + 1);
	if (!count)
		goto hole;
	trace("found physical block %Lx", (L)found->block);
	struct dev *dev = sb->devmap->dev;
	assert(dev->bits >= 8 && dev->fd);
	return diskread(dev->fd, buffer->data, sb->blocksize, found->block << dev->bits);
hole:
	trace("unmapped block %Lx", (L)buffer->index);
	memset(buffer->data, 0, sb->blocksize);
	return 0;
}

int filemap_blockwrite(struct buffer *buffer)
{
	struct inode *inode = buffer->map->inode;
	struct sb *sb = inode->sb;
	warn("block write <%Lx:%Lx>", (L)inode->inum, (L)buffer->index);
	if (buffer->index & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	if (buffer_empty(buffer))
		warn("egad, wrote an invalid buffer");

	/* Generate extent */
	unsigned ends[2] = { buffer->index, buffer->index};
	for (int up = 0, sign = -1; up < 2; up++, sign = -sign) {
		while (ends[1] - ends[0] + 1 < MAX_EXTENT) {
			struct buffer *nextbuf = findblk(buffer->map, ends[up] + sign);
			if (!nextbuf)
				break;
			unsigned next = nextbuf->index, dirty = buffer_dirty(nextbuf);
			brelse(nextbuf);
			if (!dirty)
				break;
			ends[up] = next; /* what happens to the beer you send */
		}
	}
	struct dev *dev = sb->devmap->dev;
	assert(dev->bits >= 8 && dev->fd);
	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels)
		return -EIO;
#ifndef filemap_included
	unsigned segs = 0, i;
	index_t start = ends[0], limit = ends[1] + 1;

	printf("---- extent 0x%Lx/%Lx ----\n", (L)start, (L)limit - start);
	/* Probe below extent start to include possible overlap */
	if ((err = probe(&inode->btree, start - MAX_EXTENT, path)))
		return err;

	struct dwalk *walk = &(struct dwalk){ };
	struct dleaf *leaf = path[levels].buffer->data;
	struct extent seg[1000];
	dwalk_probe(leaf, sb->blocksize, walk, 0); // start at beginning of leaf just for now

	/* skip extents below start */
	for (struct extent *extent; (extent = dwalk_next(walk));)
		if (dwalk_index(walk) + extent_count(*extent) >= start) {
			dwalk_back(walk);
			break;
		}
	struct dwalk rewind = *walk;
	printf("prior extents:");
	for (struct extent *extent; (extent = dwalk_next(walk));)
		printf(" 0x%Lx => %Lx/%x;", (L)dwalk_index(walk), (L)extent->block, extent_count(*extent));
	printf("\n");

	printf("---- rewind to 0x%Lx => %Lx/%x ----\n", (L)dwalk_index(&rewind), (L)rewind.extent->block, extent_count(*rewind.extent));
	*walk = rewind;

	// !!!<handle overlapping extent>!!! //

	struct extent *next_extent = NULL;
	index_t index = start, offset = 0;
	while (index < limit) {
		trace("index %Lx, limit %Lx", (L)index, (L)limit);
		if (next_extent) {
			trace("pass %Lx/%x", (L)next_extent->block, extent_count(*next_extent));
			seg[segs++] = *next_extent;

			unsigned count = extent_count(*next_extent);
			if (start > dwalk_index(walk))
				count -= start - dwalk_index(walk);
			index += count;
		}
		next_extent = dwalk_next(walk);
		index_t next_index = limit;
		if (next_extent) {
			next_index = dwalk_index(walk);
			if (next_index < start) {
				offset = start - next_index;
				next_index = start;
			}
		}
		int gap = next_index - index;
		trace("offset = %i, gap = %i", offset, gap);
		if (gap == 0)
			continue;
		if (index + gap > limit)
			gap = limit - index;
		trace("fill gap at %Lx/%x", index, gap);
		block_t block = balloc_extent(sb, gap); // goal ???
		if (block == -1)
			goto nospace; // clean up !!!
		seg[segs++] = extent(block, gap);
		index += gap;
	}

	while (next_extent) {
		trace("save tail");
		seg[segs++] = *next_extent;
		next_extent = dwalk_next(walk);
	}

	printf("segs (offset = %Lx):", (L)offset);
	for (i = 0, index = start; i < segs; i++) {
		printf(" %Lx => %Lx/%x;", (L)index - offset, (L)seg[i].block, extent_count(seg[i]));
		index += extent_count(seg[i]);
	}
	printf(" (%i)\n", segs);

if (0) {
	*walk = rewind;
	for (i = 0, index = start - offset; i < segs; i++, index += seg[i].count)
		dwalk_mock(walk, index, extent(seg[i].block, extent_count(seg[i])));
	printf("need %i data and %i index bytes\n", walk->mock.free, -walk->mock.used);
}
	/* split leaf if necessary */

	*walk = rewind;
	dwalk_chop_after(walk);
	dleaf_dump(sb->blocksize, leaf);
	for (i = 0, index = start - offset; i < segs; i++) {
		trace("pack 0x%Lx => %Lx/%x", index, (L)seg[i].block, extent_count(seg[i]));
		dwalk_pack(walk, index, extent(seg[i].block, extent_count(seg[i])));
		index += extent_count(seg[i]);
	}
	dleaf_dump(sb->blocksize, leaf);

	// !!!<handle overlapping extent>!!! //
	/* assert we used exactly the expected space */
	//assert(??? == ???);
	/* check leaf */
	if (0)
		goto eek;

	/* fake the actual write for now */
	for (index = start; index < limit; index++)
		brelse(set_buffer_uptodate(getblk(inode->map, index)));

	return 0;
#else
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	unsigned count = 0;
	struct extent *found = dleaf_lookup(&inode->btree, path[levels].buffer->data, buffer->index, &count);
	block_t physical;
	if (count) {
		physical = found->block;
		trace("found block [%Lx]", (L)physical);
	} else {
		physical = balloc(sb);
		if (physical == -1)
			goto nospace;
		struct extent *store = tree_expand(&inode->btree, buffer->index, sizeof(struct extent), path);
		if (!store)
			goto eek;
		*store = (struct extent){ .block = physical };
	}
	release_path(path, levels + 1);
	return diskwrite(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
#endif
nospace:
	err = -ENOSPC;
eek:
	warn("could not add extent to tree: %s", strerror(-err));
// !!!	free_block(sb, physical);
	return -EIO;
}

struct map_ops filemap_ops = {
	.bread = filemap_blockread,
	.bwrite = filemap_blockwrite,
};

#ifndef filemap_included
int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	SB = &(struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = size >> dev->bits,
	};
	sb->bitmap = &(struct inode){ .sb = sb, .map = new_map(dev, &filemap_ops) },
	sb->bitmap->map->inode = sb->bitmap;
	init_buffers(dev, 1 << 20);
	struct inode *inode = &(struct inode){ .sb = sb, .map = new_map(dev, &filemap_ops) };
	inode->btree = new_btree(sb, &dtree_ops); // error???
	inode->map->inode = inode;
	inode = inode;

	brelse_dirty(getblk(inode->map, 5));
	brelse_dirty(getblk(inode->map, 6));
	printf("flush... %s\n", strerror(-flush_buffers(inode->map)));

	brelse_dirty(getblk(inode->map, 6));
	brelse_dirty(getblk(inode->map, 7));
	printf("flush... %s\n", strerror(-flush_buffers(inode->map)));

	return 0;

	brelse_dirty(getblk(inode->map, 0));
	brelse_dirty(getblk(inode->map, 1));
	brelse_dirty(getblk(inode->map, 2));
	brelse_dirty(getblk(inode->map, 3));
	printf("flush... %s\n", strerror(-flush_buffers(inode->map)));

	brelse_dirty(getblk(inode->map, 0));
	brelse_dirty(getblk(inode->map, 1));
	brelse_dirty(getblk(inode->map, 2));
	brelse_dirty(getblk(inode->map, 3));
	brelse_dirty(getblk(inode->map, 4));
	brelse_dirty(getblk(inode->map, 5));
	brelse_dirty(getblk(inode->map, 6));
	printf("flush... %s\n", strerror(-flush_buffers(inode->map)));

	//show_buffers(inode->map);
	return 0;
}
#endif
