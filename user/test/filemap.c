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

int filemap_write(struct buffer *buffer)
{
	struct inode *inode = buffer->map->inode;
	struct sb *sb = inode->sb;
	struct dev *dev = sb->devmap->dev;
	warn("block write <%Lx:%Lx>", (L)inode->inum, buffer->index);
	if (buffer->index & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	assert(dev->bits >= 8 && dev->fd);
	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels)
		return -EIO;
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	unsigned count = 0;
	struct extent *found = dleaf_lookup(&inode->btree, path[levels].buffer->data, buffer->index, &count);
	//dleaf_dump(&inode->btree, path[levels].buffer->data);

	block_t physical;

	if (buffer_empty(buffer))
		warn("egad, wrote an invalid buffer");
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
		printf("extent from %x to %x\n", ends[0], ends[1]);
#if 0
#else
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
	warn("cannot add extent to tree: %s", strerror(-err));
	free_block(sb, physical);
	return -EIO;
}

int filemap_read(struct buffer *buffer)
{
	struct inode *inode = buffer->map->inode;
	struct sb *sb = inode->sb;
	struct dev *dev = sb->devmap->dev;
	warn("block read <%Lx:%Lx>", (L)inode->inum, buffer->index);
	if (buffer->index & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	assert(dev->bits >= 8 && dev->fd);
	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels)
		goto unmapped;
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	unsigned count = 0;
	struct extent *found = dleaf_lookup(&inode->btree, path[levels].buffer->data, buffer->index, &count);
	//dleaf_dump(&inode->btree, path[levels].buffer->data);

	block_t physical;

	release_path(path, levels + 1);
	if (!count)
		goto unmapped;
	physical = found->block;
	trace("found physical block %Lx", (long long)physical);
	return diskread(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
unmapped:
	/* found a hole */
	trace("unmapped block %Lx", buffer->index);
	memset(buffer->data, 0, sb->blocksize);
	return 0;
}

struct map_ops filemap_ops = { .bread = filemap_read, .bwrite = filemap_write };

#ifndef filemap_included
int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
//	int err = 0;
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	init_buffers(dev, 1 << 20);
	SB = &(struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = size >> dev->bits,
	};

	sb = sb;
	return 0;
}
#endif
