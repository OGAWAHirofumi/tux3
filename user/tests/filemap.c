#ifndef trace
#define trace trace_off
#endif

#include "../filemap.c"
#include "test.h"

static void clean_main(struct sb *sb, struct inode *inode)
{
	iput(inode);
	put_super(sb);
}

static void add_maps(struct inode *inode, block_t index, struct seg *seg,
		     int nr_segs)
{
	for (int i = 0; i < nr_segs; i++) {
		struct seg *s = &seg[i];
		for (unsigned j = 0; j < s->count; j++) {
			struct buffer_head *buf;
			buf = blockget(inode->map, index + j);
			buf = blockdirty(buf, inode->i_sb->delta);
			memset(buf->data, 0, inode->i_sb->blocksize);
			*(block_t *)buf->data = s->block + j;
			mark_buffer_dirty_non(buf);
			blockput(buf);
		}
		index += s->count;
	}
}

/* Create segments, then save state to buffer */
static int d_map_region(struct inode *inode, block_t start, unsigned count,
			struct seg *seg, unsigned max_segs, enum map_mode mode)
{
	int nr_segs;
	/* this should be called with "mode != MAP_READ" */
	assert(mode != MAP_READ);
	nr_segs = map_region(inode, start, count, seg, max_segs, mode);
	if (nr_segs > 0)
		add_maps(inode, start, seg, nr_segs);
	return nr_segs;
}

static void check_maps(struct inode *inode, block_t index, struct seg *seg,
		       int nr_segs)
{
	for (int i = 0; i < nr_segs; i++) {
		struct seg *s = &seg[i];
		for (unsigned j = 0; j < s->count; j++) {
			struct buffer_head *buf;
			buf = peekblk(inode->map, index + j);
			if (s->state == SEG_HOLE)
				test_assert(buf == NULL);
			else {
				block_t blk = *(block_t *)buf->data;
				test_assert(blk == s->block + j);
				blockput(buf);
			}
		}
		index += s->count;
	}
}

/* Check returned segments are same state with buffer */
static int check_map_region(struct inode *inode, block_t start, unsigned count,
			    struct seg *seg, unsigned max_segs)
{
	int nr_segs;
	nr_segs = map_region(inode, start, count, seg, max_segs, MAP_READ);
	if (nr_segs > 0)
		check_maps(inode, start, seg, nr_segs);
	return nr_segs;
}

struct test_data {
	block_t index;
	unsigned count;
	enum map_mode mode;
};

/* Test basic operations */
static void test01(struct sb *sb, struct inode *inode)
{
	/*
	 * FIXME: map_region() are not supporting to read segments on
	 * multiple leaves at once.
	 */
#define CAN_HANDLE_A_LEAF	1

	/* Create by ascending order */
	if (test_start("test01.1")) {
		struct seg seg;
		int err, segs;

		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = d_map_region(inode, 2*i, 1, &seg, 1, MAP_WRITE);
			test_assert(segs == 1);
		}
#ifdef CAN_HANDLE_A_LEAF
		for (int i = 0; i < 30; i++) {
			segs = check_map_region(inode, 2*i, 1, &seg, 1);
			test_assert(segs == 1);
		}
#else
		segs = check_map_region(inode, 0, 30*2, map, ARRAY_SIZE(map));
		test_assert(segs == 30*2);
#endif

		/* btree_chop and dleaf_chop test */
		int index = 31*2;
		while (index--) {
			err = btree_chop(&inode->btree, index, TUXKEY_LIMIT);
			test_assert(!err);
#ifdef CAN_HANDLE_A_LEAF
			for (int i = 0; i < 30; i++) {
				if (index <= i*2)
					break;
				segs = check_map_region(inode, 2*i, 1, &seg, 1);
				test_assert(segs == 1);
			}
#else
			segs = check_map_region(inode, 0, 30*2, map,
						ARRAY_SIZE(map));
			test_assert(segs == i*2);
#endif
		}

		/* Check if truncated all */
		segs = map_region(inode, 0, INT_MAX, &seg, 1, MAP_READ);
		test_assert(segs == 1);
		test_assert(seg.count == INT_MAX);
		test_assert(seg.state == SEG_HOLE);

		test_assert(force_delta(sb) == 0);
		clean_main(sb, inode);
	}
	test_end();

	/* Create by descending order */
	if (test_start("test01.2")) {
		struct seg seg;
		int err, segs;

		for (int i = 30; i >= 0; i--) {
			segs = d_map_region(inode, 2*i, 1, &seg, 1, MAP_WRITE);
			test_assert(segs == 1);
		}
#ifdef CAN_HANDLE_A_LEAF
		for (int i = 30; i >= 0; i--) {
			segs = check_map_region(inode, 2*i, 1, &seg, 1);
			test_assert(segs == 1);
		}
#else
		segs = check_map_region(inode, 0, 30*2, map, ARRAY_SIZE(map));
		test_assert(segs == i*2);
#endif

		err = btree_chop(&inode->btree, 0, TUXKEY_LIMIT);
		test_assert(!err);

		/* Check if truncated all */
		segs = map_region(inode, 0, INT_MAX, &seg, 1, MAP_READ);
		test_assert(segs == 1);
		test_assert(seg.count == INT_MAX);
		test_assert(seg.state == SEG_HOLE);

		test_assert(force_delta(sb) == 0);
		clean_main(sb, inode);
	}
	test_end();

	test_assert(force_delta(sb) == 0);
	clean_main(sb, inode);
}

/* Test redirect mode (create == 2) */
static void test02(struct sb *sb, struct inode *inode)
{
	struct seg map[32];

	struct test_data data[] = {
		{ .index = 5,  .count = 64, .mode = MAP_WRITE, },
		{ .index = 10, .count = 20, .mode = MAP_REDIRECT, },
		{ .index = 80, .count = 10, .mode = MAP_REDIRECT, },
	};

	int total_segs = 0;
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		int segs1, segs2;

		segs1 = d_map_region(inode, data[i].index, data[i].count,
				    map, ARRAY_SIZE(map), data[i].mode);
		test_assert(segs1 > 0);
		total_segs += segs1;

		segs2 = check_map_region(inode, data[i].index, data[i].count,
					 map, ARRAY_SIZE(map));
		test_assert(segs1 == segs2);
	}

	/* Check whole rage from 0 */
	int segs = check_map_region(inode, 0, 200, map, ARRAY_SIZE(map));
	test_assert(segs >= total_segs);

	/* Clear dirty page to prevent to call map_region again */
	truncate_inode_pages(mapping(inode), 0);

	test_assert(force_delta(sb) == 0);
	clean_main(sb, inode);
}

/* Test overwrite seg entirely inside existing */
static void test03(struct sb *sb, struct inode *inode)
{
	struct seg map1[32], map2[32];
	int segs1, segs2;

	/* Create range */
	segs1 = d_map_region(inode, 2, 5, map1, ARRAY_SIZE(map1), MAP_WRITE);
	test_assert(segs1 > 0);
	segs2 = check_map_region(inode, 2, 5, map2, ARRAY_SIZE(map2));
	test_assert(segs1 == segs2);

	/* Overwrite range */
	segs1 = d_map_region(inode, 4, 1, map1, ARRAY_SIZE(map1), MAP_WRITE);
	test_assert(segs1 > 0);
	segs2 = check_map_region(inode, 4, 1, map1, ARRAY_SIZE(map1));
	test_assert(segs1 == segs2);

	segs1 = check_map_region(inode, 2, 5, map1, ARRAY_SIZE(map1));
	test_assert(segs1 > segs2);
	test_assert(map1[0].block == map2[0].block);
	test_assert(map1[0].count < map2[0].count);
	test_assert(map1[0].count == 2);
	test_assert(map1[1].block != map1[0].block);
	test_assert(map1[1].count == 1);
	test_assert(map1[2].block != map1[1].block);
	test_assert(map1[2].count == 2);

	/* Check whole rage from 0 */
	segs2 = check_map_region(inode, 0, 200, map2, ARRAY_SIZE(map2));
	test_assert(segs2 >= segs1);

	/* Clear dirty page to prevent to call map_region again */
	truncate_inode_pages(mapping(inode), 0);

	test_assert(force_delta(sb) == 0);
	clean_main(sb, inode);
}

/* Test overwrite extent and hole at once */
static void test04(struct sb *sb, struct inode *inode)
{
	struct seg map1[32], map2[32];
	int segs1, segs2;

	/* Create extents */
	segs1 = d_map_region(inode, 2, 2, map1, ARRAY_SIZE(map1), MAP_WRITE);
	test_assert(segs1 > 0);
	segs2 = check_map_region(inode, 2, 2, map2, ARRAY_SIZE(map2));
	test_assert(segs1 == segs2);

	/* Overwrite extent and hole at once */
	segs1 = d_map_region(inode, 2, 4, map1, ARRAY_SIZE(map1), MAP_WRITE);
	test_assert(segs1 > 0);
	segs2 = check_map_region(inode, 2, 4, map1, ARRAY_SIZE(map1));
	test_assert(segs1 == segs2);

	/* Check whole rage from 0 */
	segs2 = check_map_region(inode, 0, 200, map2, ARRAY_SIZE(map2));
	test_assert(segs2 >= segs1);

	/* Clear dirty page to prevent to call map_region again */
	truncate_inode_pages(mapping(inode), 0);

	test_assert(force_delta(sb) == 0);
	clean_main(sb, inode);
}

static void __test05(struct test_data data[], int nr, struct inode *inode)
{
	struct test_data *t = data;
	struct seg map[32];
	int total_segs = 0;

	for (int i = 0; i < nr; i++, t++) {
		int segs1, segs2;

		segs1 = d_map_region(inode, t->index, t->count,
				     map, ARRAY_SIZE(map), t->mode);
		test_assert(segs1 > 0);
		total_segs += segs1;

		segs2 = check_map_region(inode, t->index, t->count,
					 map, ARRAY_SIZE(map));
		test_assert(segs1 == segs2);
	}
#if 0
	/* Check whole rage */
	block_t idx = data[0].index;
	unsigned end = data[nr - 1].index + data[nr - 1].count + 10;
	segs = check_map_region(inode, idx, end - idx, map, ARRAY_SIZE(map));
	test_assert(segs >= total_segs);
#endif
}

/* Test to write block to hole */
static void test05(struct sb *sb, struct inode *inode)
{
	struct test_data data[][3] = {
		/* Test case 1 */
		{
			{ .index = 2, .count = 1, .mode = MAP_WRITE, },
			{ .index = 6, .count = 1, .mode = MAP_WRITE, },
			{ .index = 4, .count = 1, .mode = MAP_WRITE, },
		},
		/* Test case 2 */
		{
			{ .index = 0x1100000, .count = 0x40, .mode=MAP_WRITE, },
			{ .index =  0x800000, .count = 0x40, .mode=MAP_WRITE, },
			{ .index =  0x800040, .count = 0x40, .mode=MAP_WRITE, },
		},
	};

	for (int test = 0; test < ARRAY_SIZE(data); test++) {
		__test05(data[test], ARRAY_SIZE(data[test]), inode);

		int err = btree_chop(&inode->btree, 0, TUXKEY_LIMIT);
		test_assert(!err);
	}

	test_assert(force_delta(sb) == 0);
	clean_main(sb, inode);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);

	char *name = argv[1];
	int fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	u64 size = 1 << 24;
	assert(!ftruncate(fd, size));

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 20, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, size >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	test_assert(make_tux3(sb) == 0);

	struct tux_iattr iattr = { .mode = S_IFREG | 0644, };
	struct inode *inode = tuxcreate(sb->rootdir, "foo", 3, &iattr);

	test_assert(force_rollup(sb) == 0);

	test_init(argv[0]);

	if (test_start("test01"))
		test01(sb, inode);
	test_end();

	if (test_start("test02"))
		test02(sb, inode);
	test_end();

	if (test_start("test03"))
		test03(sb, inode);
	test_end();

	if (test_start("test04"))
		test04(sb, inode);
	test_end();

	if (test_start("test05"))
		test05(sb, inode);
	test_end();

	clean_main(sb, inode);
	return test_failures();
}
