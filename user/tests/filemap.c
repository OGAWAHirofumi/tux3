#include "../filemap.c"
#include "diskio.h"	/* for fdsize64() */

static void check_created_seg(struct seg *seg)
{
	assert(seg->block > 0);
	assert(seg->count > 0);
}

static void add_maps(struct inode *inode, block_t index, struct seg map[], int segs)
{
	struct buffer_head *buffer;
	for (int i = 0; i < segs; i++) {
		for (unsigned j = 0; j < map[i].count; j++) {
			buffer = blockget(inode->map, index + j);
			*(block_t *)buffer->data = map[i].block + j;
			blockput(buffer);
		}
		index += map[i].count;
	}
}

static void check_maps(struct inode *inode, block_t index, struct seg map[], int segs)
{
	struct buffer_head *buffer;
	for (int i = 0; i < segs; i++) {
		for (unsigned j = 0; j < map[i].count; j++) {
			buffer = peekblk(inode->map, index + j);
			if (map[i].state == SEG_HOLE)
				assert(buffer == NULL);
			else {
				block_t block = *(block_t *)buffer->data;
				assert(block == map[i].block + j);
				blockput(buffer);
			}
		}
		index += map[i].count;
	}
}

static int d_map_region(struct inode *inode, block_t start, unsigned count, struct seg map[], unsigned max_segs, int create)
{
	int segs = map_region(inode, start, count, map, max_segs, create);
	if (segs) {
		if (create)
			add_maps(inode, start, map, segs);
		else
			check_maps(inode, start, map, segs);
	}
	return segs;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	char *name = argv[1];
	int fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(!ftruncate(fd, 1 << 24));
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 20, 0);

	struct disksuper super = INIT_DISKSB(dev->bits, size >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = rapid_open_inode(sb, NULL, 0);
	sb->logmap = rapid_open_inode(sb, dev_errio, 0);
	sb->bitmap = rapid_open_inode(sb, filemap_extent_io, 0);
	struct inode *inode = rapid_open_inode(sb, filemap_extent_io, 0);
	init_btree(&inode->btree, sb, no_root, &dtree_ops);
	int err = alloc_empty_btree(&inode->btree);
	assert(!err);

	block_t nextalloc = sb->nextalloc;
	struct seg map[64];
	int segs;

	if (1) {
		for (int i = 0; i < 10; i++)
			segs = map_region(inode, 2*i, 1, map, 2, 1);
		show_segs(map, segs);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* redirect test */
		segs = d_map_region(inode, 5, 64, map, 10, 1);
		segs = d_map_region(inode, 10, 20, map, 10, 2);
		segs = d_map_region(inode, 80, 10, map, 10, 2);
		segs = d_map_region(inode, 0, 200, map, 10, 0);
		invalidate_buffers(inode->map);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* create seg entirely inside existing */
		segs = map_region(inode, 2, 5, map, 10, 1); show_segs(map, segs);
		segs = map_region(inode, 4, 1, map, 10, 1); show_segs(map, segs);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* seek[0] and seek[1] are same position */
		segs = map_region(inode, 0x2, 0x1, map, 10, 1);
		segs = map_region(inode, 0x6, 0x1, map, 10, 1);
		segs = map_region(inode, 0x4, 0x1, map, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}
	if (1) { /* another seek[0] and seek[1] are same position */
		segs = map_region(inode, 0x1100000, 0x40, map, 10, 1);
		segs = map_region(inode, 0x800000, 0x40, map, 10, 1);
		segs = map_region(inode, 0x800040, 0x40, map, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}

	if (1) {
		struct seg seg;
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
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
				map_region(inode, i*2, 1, &seg, 1, 0);
				assert(map[j].block == seg.block);
				assert(map[j].count == seg.count);
			}
		}
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 10, j = 0; i--; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 10, j = 0; i--; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
		}
		show_tree_range(&inode->btree, 0, -1);
		/* 0/2: 0 => 3/1; 2 => 2/1; */
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
		}
		/* 0/2: 38 => 3/1; 3a => 2/1; */
		show_tree_range(&inode->btree, 0, -1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		err = unstash(sb, &sb->defree, apply_defered_bfree);
		assert(!err);
		sb->nextalloc = nextalloc;
	}
#if 1
	/* Can't alloc contiguous range */
	assert(balloc_from_range(sb, 0x10, 1, 1) >= 0);
	sb->nextalloc = 0xf;
	blockput_dirty(blockread(mapping(inode), 0x0));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	blockput_dirty(blockread(mapping(inode), 0x1));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	invalidate_buffers(mapping(inode));
	filemap_extent_io(blockget(mapping(inode), 1), 0);

	destroy_defer_bfree(&sb->defree);

	exit(0);
#endif

#if 1
	filemap_extent_io(blockget(mapping(inode), 5), 0);
	exit(0);
#endif

#if 0
	for (int i = 0; i < 20; i++) {
		blockput_dirty(blockget(mapping(inode), i));
		printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	}
	return 0;
#endif

#if 1
	blockput_dirty(blockget(mapping(inode), 5));
	blockput_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	blockput_dirty(blockget(mapping(inode), 6));
	blockput_dirty(blockget(mapping(inode), 7));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	exit(0);
#endif

	blockput_dirty(blockget(mapping(inode), 0));
	blockput_dirty(blockget(mapping(inode), 1));
	blockput_dirty(blockget(mapping(inode), 2));
	blockput_dirty(blockget(mapping(inode), 3));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	blockput_dirty(blockget(mapping(inode), 0));
	blockput_dirty(blockget(mapping(inode), 1));
	blockput_dirty(blockget(mapping(inode), 2));
	blockput_dirty(blockget(mapping(inode), 3));
	blockput_dirty(blockget(mapping(inode), 4));
	blockput_dirty(blockget(mapping(inode), 5));
// 	blockput_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	//show_buffers(mapping(inode));
	
	exit(0);
}
