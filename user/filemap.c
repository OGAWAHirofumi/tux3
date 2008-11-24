#ifndef trace
#define trace trace_off
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

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/filemap.c"

int filemap_block_read(struct buffer_head *buffer)
{
	return filemap_extent_io(buffer, 0);
}

int filemap_block_write(struct buffer_head *buffer)
{
	return filemap_extent_io(buffer, 1);
}

struct map_ops filemap_ops = {
	.blockread = filemap_block_read,
	.blockwrite = filemap_block_write,
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
	struct dev *dev = &(struct dev){ fd, .bits = 8 };
	SB = &(struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = size >> dev->bits,
	};
	sb->bitmap = &(struct inode){ .i_sb = sb, .map = new_map(dev, &filemap_ops) },
	sb->bitmap->map->inode = sb->bitmap;
	init_buffers(dev, 1 << 20);
	struct inode *inode = &(struct inode){ .i_sb = sb, .map = new_map(dev, &filemap_ops) };
	inode->btree = new_btree(sb, &dtree_ops); // error???
	inode->map->inode = inode;
	inode = inode;

#if 1
	brelse_dirty(blockread(mapping(inode), 0));
	brelse_dirty(blockread(mapping(inode), 1));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	filemap_extent_io(blockget(mapping(inode), 0), 0);
	return 0;
#endif

#if 1
	filemap_extent_io(blockget(mapping(inode), 5), 0);
	return 0;
#endif

#if 0
	for (int i = 0; i < 20; i++) {
		brelse_dirty(blockget(mapping(inode), i));
		printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	}
	return 0;
#endif

#if 1
	brelse_dirty(blockget(mapping(inode), 5));
	brelse_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	brelse_dirty(blockget(mapping(inode), 6));
	brelse_dirty(blockget(mapping(inode), 7));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	return 0;
#endif

	brelse_dirty(blockget(mapping(inode), 0));
	brelse_dirty(blockget(mapping(inode), 1));
	brelse_dirty(blockget(mapping(inode), 2));
	brelse_dirty(blockget(mapping(inode), 3));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	brelse_dirty(blockget(mapping(inode), 0));
	brelse_dirty(blockget(mapping(inode), 1));
	brelse_dirty(blockget(mapping(inode), 2));
	brelse_dirty(blockget(mapping(inode), 3));
	brelse_dirty(blockget(mapping(inode), 4));
	brelse_dirty(blockget(mapping(inode), 5));
	brelse_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	//show_buffers(mapping(inode));
	return 0;
}
#endif
