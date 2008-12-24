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
static void check_created_seg(struct seg *seg)
{
	assert(seg->block > 0);
	assert(seg->count > 0);
}

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
	struct sb *sb = &(struct sb){
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
	assert(!new_btree(&inode->btree, sb, &dtree_ops));
	inode->map->inode = inode;
	inode = inode;

	block_t nextalloc = sb->nextalloc;
	struct seg segvec[64];
	int segs;

	if (0) {
		for (int i = 0; i < 1; i++) {
			struct cursor *cursor = alloc_cursor(&inode->btree, 1);
			struct dwalk seek[2] = { };
			unsigned overlap[2];
			segs = find_segs(cursor, 2*i, 2*i + 1, segvec, 2, seek, overlap);
			show_segs(segvec, segs);
			segs = fill_segs(cursor, 2*i, 2*i + 1, segvec, segs, seek, overlap);
			show_segs(segvec, segs);
		}
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* create seg entirely inside existing */
		segs = get_segs(inode, 2, 5, segvec, 10, 1); show_segs(segvec, segs);
		segs = get_segs(inode, 4, 1, segvec, 10, 1); show_segs(segvec, segs);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* seek[0] and seek[1] are same position */
		segs = get_segs(inode, 0x2, 0x1, segvec, 10, 1);
		segs = get_segs(inode, 0x6, 0x1, segvec, 10, 1);
		segs = get_segs(inode, 0x4, 0x1, segvec, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}
	if (1) { /* another seek[0] and seek[1] are same position */
		segs = get_segs(inode, 0x1100000, 0x40, segvec, 10, 1);
		segs = get_segs(inode, 0x800000, 0x40, segvec, 10, 1);
		segs = get_segs(inode, 0x800040, 0x40, segvec, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) {
		struct seg seg;
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			segvec[j].block = seg.block;
			segvec[j].count = seg.count;
		}
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(segvec[j].block == seg.block);
			assert(segvec[j].count == seg.count);
		}
		show_tree_range(&inode->btree, 0, -1);
		/* tree_chop and dleaf_chop test */
		int index = 31*2;
		while (index--) {
			struct delete_info delinfo = { .key = index, };
			segs = tree_chop(&inode->btree, &delinfo, 0);
			assert(!segs);
			for (int i = 0, j = 0; i < 30; i++, j++) {
				if (index <= i*2)
					break;
				get_segs(inode, i*2, 1, &seg, 1, 0);
				assert(segvec[j].block == seg.block);
				assert(segvec[j].count == seg.count);
			}
		}
		segs = get_segs(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 10, j = 0; i--; j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			segvec[j].block = seg.block;
			segvec[j].count = seg.count;
		}
		for (int i = 10, j = 0; i--; j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(segvec[j].block == seg.block);
			assert(segvec[j].count == seg.count);
		}
		show_tree_range(&inode->btree, 0, -1);
		/* 0/2: 0 => 3/1; 2 => 2/1; */
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = get_segs(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			segvec[j].block = seg.block;
			segvec[j].count = seg.count;
		}
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = get_segs(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(segvec[j].block == seg.block);
			assert(segvec[j].count == seg.count);
		}
		/* 0/2: 38 => 3/1; 3a => 2/1; */
		show_tree_range(&inode->btree, 0, -1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = get_segs(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}

#if 1
	sb->nextalloc = 0x10;
	balloc(sb, 1);
	sb->nextalloc = 0xf;
	brelse_dirty(blockread(mapping(inode), 0x0));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	brelse_dirty(blockread(mapping(inode), 0x1));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	filemap_extent_io(blockget(mapping(inode), 1), 0);
	exit(0);
#endif

#if 1
	filemap_extent_io(blockget(mapping(inode), 5), 0);
	exit(0);
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

	exit(0);
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
	
	exit(0);
}
#endif
