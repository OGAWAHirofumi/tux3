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

int file_bread(struct buffer *buffer)
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

int file_bwrite(struct buffer *buffer)
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
	if (ends[1] - ends[0])
		printf("<<< extent from %x to %x >>>\n", ends[0], ends[1]);

	struct dev *dev = sb->devmap->dev;
	assert(dev->bits >= 8 && dev->fd);
	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels)
		return -EIO;
#if 0
	index_t index = ends[0], limit = ends[0] + 1;
	/* Probe max below extent start to include possible overlap */
	if ((err = probe(&inode->btree, index - MAX_EXTENT, path)))
		return err;
	struct dwalk *walk = &(struct dwalk){ };
	struct dleaf *leaf = path[levels].buffer->data;
	struct seg { block_t block; unsigned blocks; } seg[1000];
	unsigned last_index, last_block, last_count; // !!! initialize me
	unsigned next_index, next_block, next_count; // !!! initialize me
	unsigned segs = 0;
	dwalk_probe(sb, leaf, walk, 0); // start at beginning of leaf for now
	while (index < limit) {
		unsigned end = last_index + last_count, gap = next_index - end;
		if (gap) {
			sb->nextalloc = end;
			block_t block = balloc_extent(sb, gap);
			if (block == -1)
				goto eek; // ENOSPC !!!
			last_index = end;
			last_block = block;
			last_count = gap;
		} else {
			struct extent *extent = dwalk_next(walk);
			if (!extent)
				goto eek;
			last_index = next_index;
			last_block = next_block;
			last_count = next_count;
			next_index = dwalk_index(walk);
			next_block = extent->block;
			next_count = extent->count;
		}
		seg[segs++] = (struct seg){ last_block, last_count };
		index += last_count;
	}

	/* run mock to find out how much space we need */
	for (int i = 0; i < segs; i++) {
//		dwalk_mock(???);
	}
	/* split leaf if necessary */
	dwalk_probe(sb, leaf, walk, 0); // start at beginning of leaf for now
	/* run pack to update page */
	for (int i = 0; i < segs; i++) {
//		dwalk_pack(???);
	}
	/* assert we used exactly the expected space */
//	assert(??? == ???);
	/* check leaf */
#else
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	unsigned count = 0;
	struct extent *found = dleaf_lookup(&inode->btree, path[levels].buffer->data, buffer->index, &count);
	//dleaf_dump(&inode->btree, path[levels].buffer->data);
	block_t physical;
	if (count) {
		physical = found->block;
		trace("found block [%Lx]", (L)physical);
	} else {
		physical = balloc(sb);
		if (physical == -1) {
			err = -ENOSPC;
			goto eek;
		}
		struct extent *store = tree_expand(&inode->btree, buffer->index, sizeof(struct extent), path);
		if (!store)
			goto eek;
		*store = (struct extent){ .block = physical };
	}
	release_path(path, levels + 1);
	return diskwrite(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
#endif
eek:
	warn("could not add extent to tree: %s", strerror(-err));
// !!!	free_block(sb, physical);
	return -EIO;
}

struct map_ops filemap_ops = { .bread = file_bread, .bwrite = file_bwrite };

#ifndef filemap_included
int main(int argc, char *argv[])
{
return 0;
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
	brelse_dirty(getblk(inode->map, 0));
	brelse_dirty(getblk(inode->map, 1));
	brelse_dirty(getblk(inode->map, 2));
	brelse_dirty(getblk(inode->map, 3));
	printf("flush... %s\n", strerror(-flush_buffers(inode->map)));
	show_buffers(inode->map);
	return 0;
}
#endif
