/*
 * File index btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"
#include "test.h"

#ifndef trace
#define trace trace_on
#endif

#define NO_BALLOC_FIND
#include "balloc-dummy.c"

#include "../filemap.c"		/* for seg_alloc() */
#include "kernel/dleaf2.c"

static void clean_main(struct sb *sb, struct btree *btree)
{
	log_finish(sb);
	log_finish_cycle(sb, 1);
	destroy_defer_bfree(&sb->deunify);
	destroy_defer_bfree(&sb->defree);
	tux3_clear_dirty_inode(sb->logmap);
	free_map(btree_inode(btree)->map);
	put_super(sb);
	tux3_exit_mem();
}

static struct dleaf2 *dleaf2_create(struct btree *btree)
{
	struct dleaf2 *leaf = malloc(btree->sb->blocksize);
	if (leaf)
		btree->ops->leaf_init(btree, leaf);
	return leaf;
}

static void dleaf2_destroy(struct btree *btree, struct dleaf2 *leaf)
{
	assert(btree->ops->leaf_sniff(btree, leaf));
	free(leaf);
}

struct test_extent {
	block_t logical;
	block_t physical;
	unsigned count;
};

static void __check_seg(struct test_extent *res, block_t index,
			struct block_segment *seg, int seg_cnt)
{
	for (int i = 0; i < seg_cnt; i++) {
		test_assert(res[i].logical == index);
		test_assert(res[i].physical == seg[i].block);
		test_assert(res[i].count == seg[i].count);
		index += seg[i].count;
	}
}
#define check_seg(_res, _index, _seg, _seg_cnt) do {	\
	if (test_assert(_seg_cnt == ARRAY_SIZE(_res)))	\
		break;					\
	__check_seg(_res, _index, _seg, _seg_cnt);	\
} while (0)

static struct {
	struct block_segment *seg;
	int seg_idx;
	int seg_cnt;
} alloc_seg_info, free_seg_info;

static void dleaf2_set_alloc_seg(struct block_segment *seg, int seg_cnt)
{
	alloc_seg_info.seg = seg;
	alloc_seg_info.seg_idx = 0;
	alloc_seg_info.seg_cnt = seg_cnt;
}

static void dleaf2_set_free_seg(struct block_segment *seg, int seg_cnt)
{
	free_seg_info.seg = seg;
	free_seg_info.seg_idx = 0;
	free_seg_info.seg_cnt = seg_cnt;
}

/*
 * Hack: to control allocation details in seg_alloc(), this overwrites
 * balloc_partial.
 */
int balloc_find(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	unsigned *blocks)
{
	struct block_segment *alloc_seg =
		alloc_seg_info.seg + alloc_seg_info.seg_idx;

	assert(alloc_seg_info.seg_idx < alloc_seg_info.seg_cnt);

	*segs = 0;

	int cnt = min(alloc_seg_info.seg_cnt - alloc_seg_info.seg_idx, maxsegs);
	for (int i = 0; i < cnt && *blocks; i++) {
		*seg = *alloc_seg;
		(*segs)++;

		assert(*blocks >= seg->count);
		*blocks -= seg->count;

		seg++;
		alloc_seg++;
		alloc_seg_info.seg_idx++;
	}

	return 0;
}

static void test_seg_free(struct btree *btree, block_t block, unsigned count)
{
	if (free_seg_info.seg) {
		struct block_segment *seg;

		seg = free_seg_info.seg + free_seg_info.seg_idx;
		test_assert(seg->block == block);
		test_assert(seg->count == count);
		test_assert(free_seg_info.seg_idx < free_seg_info.seg_cnt);
		free_seg_info.seg_idx++;
	}
}

static struct btree_key_range *
dleaf2_set_req(struct dleaf_req *rq, block_t index, unsigned count,
	       struct block_segment *seg, int seg_cnt, int seg_max)
{
	*rq = (struct dleaf_req){
		.key	= {
			.start	= index,
			.len	= count,
		},
		.seg_idx	= 0,
		.seg_cnt	= seg_cnt,
		.seg_max	= seg_max,
		.seg		= seg,
		.overwrite	= 0,
		.seg_find	= seg_find,
		.seg_alloc	= seg_alloc,
		.seg_free	= test_seg_free,
	};

	return &rq->key;
}

static struct btree_key_range *
dleaf2_set_w_req(struct dleaf_req *rq, block_t index, unsigned count,
		     struct block_segment *seg, int seg_max)
{
	return dleaf2_set_req(rq, index, count, seg, 0, seg_max);
}

static struct btree_key_range *
dleaf2_set_r_req(struct dleaf_req *rq, block_t index, unsigned count,
		    struct block_segment *seg, int seg_max)
{
	return dleaf2_set_req(rq, index, count, seg, 0, seg_max);
}

/* Test dleaf2_{read,write} operations */
static void test01(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct block_segment seg[10];
	tuxkey_t hint;
	int err, ret;

	leaf = dleaf2_create(btree);
	assert(leaf);

	/*
	 * Test write "base" and overwrite by "test01.?". Then read back.
	 *
	 * base    :   |------+------+------+----+------|
	 *             3     10      15     18   20     25
	 * test01.1:   +-----+-----+
	 *             3     8    13
	 * test01.2:          +------+------+
	 *                   10     15     18
	 * test01.3:         +----+------+-----+----+
	 *                   8    12     17    19    22
	 * test01.4:                     +-------+------+
	 *                               17      20     25
	 * test01.5:                           +------+------+
	 *                                    19      23     30
	 * test01.6:                                    +------+
	 *                                             25     32
	 * test01.7:                                              +------+
	 *                                                       33      40
	 * test01.8:     +-+
	 *               5 6
	 * test01.9: +-------+-----+
	 *           0       8    13
	 * test01.a: +--+
	 *           0  3
	 * test01.b: +-+
	 *           0 2
	 * test01.c:  +---------------------------------------+
	 *            1                                      30
	 * test01.d:          +-------------+
	 *                   10            18
	 */
	struct block_segment seg1[] = {
		{ .block = 10, .count = 7, },
		{ .block = 20, .count = 5, },
		{ .block = 30, .count = 3, },
		{ .block = 40, .count = 2, },
		{ .block = 50, .count = 5, },
	};
	dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
	key = dleaf2_set_w_req(&rq, 3, 22, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(!ret);

	/* Read from 0 to 100 */
	struct test_extent res1[] = {
		{ .logical =  0, .physical =  0, .count =  3, },
		{ .logical =  3, .physical = 10, .count =  7, },
		{ .logical = 10, .physical = 20, .count =  5, },
		{ .logical = 15, .physical = 30, .count =  3, },
		{ .logical = 18, .physical = 40, .count =  2, },
		{ .logical = 20, .physical = 50, .count =  5, },
		{ .logical = 25, .physical =  0, .count = 75, },
	};
	key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.seg_cnt);

	/* Read from middle of extent */
	struct test_extent res3[] = {
		{ .logical = 13, .physical = 23, .count =  2, },
		{ .logical = 15, .physical = 30, .count =  3, },
		{ .logical = 18, .physical = 40, .count =  2, },
		{ .logical = 20, .physical = 50, .count =  3, },
	};
	key = dleaf2_set_r_req(&rq, 13, 10, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res3, 13, seg, rq.seg_cnt);

	if (test_start("test01.1")) {
		/* Overwrite from 0 */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 5, },
			{ .block = 120, .count = 5, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 10, .count = 7, },
			{ .block = 20, .count = 3, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 3, 10, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical = 110, .count =  5, },
			{ .logical =  8, .physical = 120, .count =  5, },
			{ .logical = 13, .physical =  23, .count =  2, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.2")) {
		/* Overwrite same logical address */
		struct block_segment seg2[] = {
			{ .block = 120, .count = 5, },
			{ .block = 130, .count = 3, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 20, .count = 5, },
			{ .block = 30, .count = 3, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 10, 8, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical = 120, .count =  5, },
			{ .logical = 15, .physical = 130, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.3")) {
		/* Overwrite middle of logical address */
		struct block_segment seg2[] = {
			{ .block = 120, .count = 4, },
			{ .block = 130, .count = 5, },
			{ .block = 140, .count = 2, },
			{ .block = 150, .count = 3, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 15, .count = 2, },
			{ .block = 20, .count = 5, },
			{ .block = 30, .count = 3, },
			{ .block = 40, .count = 2, },
			{ .block = 50, .count = 2, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 8, 14, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  5, },
			{ .logical =  8, .physical = 120, .count =  4, },
			{ .logical = 12, .physical = 130, .count =  5, },
			{ .logical = 17, .physical = 140, .count =  2, },
			{ .logical = 19, .physical = 150, .count =  3, },
			{ .logical = 22, .physical =  52, .count =  3, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.4")) {
		/* Overwrite end of logical address */
		struct block_segment seg2[] = {
			{ .block = 130, .count = 3, },
			{ .block = 140, .count = 5, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 32, .count = 1, },
			{ .block = 40, .count = 2, },
			{ .block = 50, .count = 5, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 17, 8, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  2, },
			{ .logical = 17, .physical = 130, .count =  3, },
			{ .logical = 20, .physical = 140, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.5")) {
		/* Overwrite beyond end of logical address */
		struct block_segment seg2[] = {
			{ .block = 140, .count = 4, },
			{ .block = 150, .count = 7, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 41, .count = 1, },
			{ .block = 50, .count = 5, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 19, 11, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  1, },
			{ .logical = 19, .physical = 140, .count =  4, },
			{ .logical = 23, .physical = 150, .count =  7, },
			{ .logical = 30, .physical =   0, .count = 70, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.6")) {
		/* Overwrite at logical address for sentinel */
		struct block_segment seg2[] = {
			{ .block = 160, .count = 7, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 25, 7, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical = 160, .count =  7, },
			{ .logical = 32, .physical =   0, .count = 68, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.7")) {
		/* Overwrite outside of logical address */
		struct block_segment seg2[] = {
			{ .block = 160, .count = 7, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 33, 7, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count =  8, },
			{ .logical = 33, .physical = 160, .count =  7, },
			{ .logical = 40, .physical =   0, .count = 60, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.8")) {
		/* Overwrite split range */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 1, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 12, .count =  1, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 5, 1, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  2, },
			{ .logical =  5, .physical = 110, .count =  1, },
			{ .logical =  6, .physical =  13, .count =  4, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.9")) {
		/* Overwrite from before minimum logical address */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 8, },
			{ .block = 120, .count = 5, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 10, .count =  7, },
			{ .block = 20, .count =  3, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 0, 13, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical = 110, .count =  8, },
			{ .logical =  8, .physical = 120, .count =  5, },
			{ .logical = 13, .physical =  23, .count =  2, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.a")) {
		/* Overwrite from less than minimum logical to minimum */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 3, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 0, 3, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical = 110, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.b")) {
		/* Overwrite only before minimum logical address */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 2, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 0, 2, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical = 110, .count =  2, },
			{ .logical =  2, .physical =   0, .count =  1, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.c")) {
		/* Overwrite all */
		struct block_segment seg2[] = {
			{ .block = 110, .count = 29, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 10, .count = 7, },
			{ .block = 20, .count = 5, },
			{ .block = 30, .count = 3, },
			{ .block = 40, .count = 2, },
			{ .block = 50, .count = 5, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 1, 29, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  1, },
			{ .logical =  1, .physical = 110, .count = 29, },
			{ .logical = 30, .physical =   0, .count = 70, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test01.d")) {
		/* Overwrite some address, and shrink total count */
		struct block_segment seg2[] = {
			{ .block = 120, .count = 8, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		struct block_segment seg3[] = {
			{ .block = 20, .count = 5, },
			{ .block = 30, .count = 3, },
		};
		dleaf2_set_free_seg(seg3, ARRAY_SIZE(seg3));
		key = dleaf2_set_w_req(&rq, 10, 8, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!ret);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical = 120, .count =  8, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();

	dleaf2_destroy(btree, leaf);
	clean_main(sb, btree);
}

/* Test dleaf2_write in the case of no space in leaf */
static void test02(struct sb *sb, struct btree *btree)
{
#define BASE	0x1000
	struct block_segment seg[10];
	struct dleaf2 *leaf1, *leaf2;
	struct dleaf_req rq;
	struct btree_key_range *key;
	tuxkey_t hint, newkey;
	int err, ret;

	leaf1 = dleaf2_create(btree);
	assert(leaf1);
	leaf2 = dleaf2_create(btree);
	assert(leaf2);

	/* Make full dleaf (-2 is for hole from 0 and sentinel) */
	for (int i = 0; i < btree->entries_per_leaf - 2; i++) {
		struct block_segment seg1[] = {
			{ .block = 0x100 + i, .count = 1, },
		};
		dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
		key = dleaf2_set_w_req(&rq, BASE + i, 1, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
		test_assert(!ret);
	}

	/* Can't write at all */
	struct block_segment seg1[] = {
		{ .block = 0x200, .count = 1, },
	};
	dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
	key = dleaf2_set_w_req(&rq, 0x100000, 1, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
	test_assert(ret == BTREE_DO_SPLIT);
	test_assert(rq.seg_idx == 0);

	/* Can't overwrite at all */
	struct block_segment seg2[] = {
		{ .block = 0x200, .count = 1, },
	};
	dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
	key = dleaf2_set_w_req(&rq, BASE / 2, 1, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
	test_assert(ret == BTREE_DO_SPLIT);
	test_assert(rq.seg_idx == 0);

	/* Can write partially */
	struct block_segment seg3[] = {
		{ .block = 0x200, .count = 2, },
		{ .block = 0x300, .count = 1, },
		{ .block = 0x301, .count = 1, },
	};
	tuxkey_t index = BASE + (btree->entries_per_leaf - 2 - seg3[0].count);
	dleaf2_set_alloc_seg(seg3, ARRAY_SIZE(seg3));
	key = dleaf2_set_w_req(&rq, index, 4, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
	test_assert(ret == BTREE_DO_SPLIT);
	test_assert(rq.seg_idx == 2);

	/* Check made in seg3[] */
	struct block_segment seg4[10];
	struct dleaf_req read_rq;
	struct btree_key_range *read_key;
	struct test_extent res1[] = {
		{ .logical = index,     .physical = 0x200, .count = 2, },
		{ .logical = index + 2, .physical = 0x300, .count = 1, },
		{ .logical = index + 3, .physical = 0,     .count = 1, },
	};
	read_key = dleaf2_set_r_req(&read_rq, index, 4, seg4, ARRAY_SIZE(seg4));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf1, read_key);
	test_assert(!err);
	check_seg(res1, index, seg4, read_rq.seg_cnt);

	/* Split, then continue remaining write */
	newkey = dleaf2_split(btree, hint, leaf1, leaf2);
	test_assert(newkey == hint);

	ret = dleaf2_write(btree, newkey, TUXKEY_LIMIT, leaf2, key, &hint);
	test_assert(!ret);
	test_assert(rq.seg_idx == 3);

	struct test_extent res2[] = {
		{ .logical = index + 0, .physical = 0x200, .count = 2, },
		{ .logical = index + 2, .physical = 0x300, .count = 1, },
		{ .logical = index + 3, .physical = 0x301, .count = 1, },
	};
	check_seg(res2, index, seg, rq.seg_cnt);

	dleaf2_destroy(btree, leaf1);
	dleaf2_destroy(btree, leaf2);
	clean_main(sb, btree);
}

/* Test dleaf2_chop operation */
static void test03(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct block_segment seg[10];
	tuxkey_t hint;
	int err, ret;

	leaf = dleaf2_create(btree);
	assert(leaf);

	/*
	 * base    :          |-------|      |---+-------|
	 *           0        10      15    18  20     25
	 * test02.1:              |
	 *                       13
	 * test02.2:                         |
	 *                                   18
	 * test02.3:                  |
	 *                           15
	 * test02.4:      |
	 *                5
	 * test02.5:                                          |
	 *                                                    30
	 */
	struct block_segment seg1[] = {
		{ .block = 20, .count =  5, },
		{ .block =  0, .count =  3, },
		{ .block = 40, .count =  2, },
		{ .block = 50, .count =  5, },
	};
	dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
	key = dleaf2_set_w_req(&rq, 10, 15, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(!ret);

	struct test_extent res1[] = {
		{ .logical =  0, .physical =  0, .count = 10, },
		{ .logical = 10, .physical = 20, .count =  5, },
		{ .logical = 15, .physical =  0, .count =  3, },
		{ .logical = 18, .physical = 40, .count =  2, },
		{ .logical = 20, .physical = 50, .count =  5, },
		{ .logical = 25, .physical =  0, .count = 75, },
	};
	key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.seg_cnt);

	if (test_start("test03.1")) {
		/* Chop at middle of logical addresses */
		ret = dleaf2_chop(btree, 13, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 20, .count =  3, },
			{ .logical = 13, .physical =  0, .count = 87, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test03.2")) {
		/* Chop at start of logical address */
		ret = dleaf2_chop(btree, 18, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 20, .count =  5, },
			{ .logical = 15, .physical =  0, .count = 85, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test03.3")) {
		/* Chop at end of logical addresses */
		ret = dleaf2_chop(btree, 15, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 20, .count =  5, },
			{ .logical = 15, .physical =  0, .count = 85, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test03.4")) {
		/* Chop at before minimum */
		ret = dleaf2_chop(btree, 5, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical = 0, .physical = 0, .count = 100, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test03.5")) {
		/* Chop at outside of last logical address */
		ret = dleaf2_chop(btree, 30, TUXKEY_LIMIT, leaf);
		test_assert(ret == 0);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 20, .count =  5, },
			{ .logical = 15, .physical =  0, .count =  3, },
			{ .logical = 18, .physical = 40, .count =  2, },
			{ .logical = 20, .physical = 50, .count =  5, },
			{ .logical = 25, .physical =  0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf);
		clean_main(sb, btree);
	}
	test_end();

	dleaf2_destroy(btree, leaf);
	clean_main(sb, btree);
}

/* Test dleaf2_split operations */
static void test04(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf1, *leaf2;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct block_segment seg[10];
	tuxkey_t hint, newkey;
	int err, ret;

	leaf1 = dleaf2_create(btree);
	assert(leaf1);
	leaf2 = dleaf2_create(btree);
	assert(leaf2);

	/*
	 * base    :          |--------+-----+--+-------|
	 *           0        10      15    18  20      25
	 */
	struct block_segment seg1[] = {
		{ .block = 10, .count =  5, },
		{ .block = 20, .count =  3, },
		{ .block = 30, .count =  2, },
		{ .block = 40, .count =  5, },
	};
	dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
	key = dleaf2_set_w_req(&rq, 10, 15, seg, ARRAY_SIZE(seg));
	ret = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
	test_assert(!ret);

	/* Test split */
	newkey = dleaf2_split(btree, 18, leaf1, leaf2);
	test_assert(newkey == 18);	/* current choose is 18 */

	struct test_extent res1[] = {
		{ .logical =  0, .physical =  0, .count = 10, },
		{ .logical = 10, .physical = 10, .count =  5, },
		{ .logical = 15, .physical = 20, .count =  3, },
	};
	key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, newkey, leaf1, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.seg_cnt);

	struct test_extent res2[] = {
		{ .logical = 18, .physical = 30, .count =  2, },
		{ .logical = 20, .physical = 40, .count =  5, },
		{ .logical = 25, .physical =  0, .count = 75, },
	};
	key = dleaf2_set_r_req(&rq, newkey, 100 - newkey, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, newkey, TUXKEY_LIMIT, leaf2, key);
	test_assert(!err);
	check_seg(res2, newkey, seg, rq.seg_cnt);

	dleaf2_destroy(btree, leaf1);
	dleaf2_destroy(btree, leaf2);
	clean_main(sb, btree);
}

/* Test dleaf2_merge operations */
static void test05(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf1, *leaf2;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct block_segment seg[10];
	tuxkey_t hint;
	int err, ret;

	leaf1 = dleaf2_create(btree);
	assert(leaf1);
	leaf2 = dleaf2_create(btree);
	assert(leaf2);

	/*
	 * test04.1:          |--------+------|   |       +-----|
	 *           0        10      15     18  20      25     30
	 * test04.2:          |--------+-----||---+-------|
	 *           0        10      15     18  20      25
	 */
	if (test_start("test05.1")) {
		/*
		 * The seg1 end and seg2 start are not same, and seg2
		 * start is hole.
		 */
		struct block_segment seg1[] = {
			{ .block = 10, .count =  5, },
			{ .block = 20, .count =  3, },
		};
		dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
		key = dleaf2_set_w_req(&rq, 10, 8, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, 18, leaf1, key, &hint);
		test_assert(!ret);

		struct block_segment seg2[] = {
			{ .block =  0, .count =  5, },
			{ .block = 40, .count =  5, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		key = dleaf2_set_w_req(&rq, 20, 10, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 20, TUXKEY_LIMIT, leaf2, key, &hint);
		test_assert(!ret);

		/* Test merge */
		ret = dleaf2_merge(btree, leaf1, leaf2);
		test_assert(ret == 1);

		struct test_extent res[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 10, .count =  5, },
			{ .logical = 15, .physical = 20, .count =  3, },
			{ .logical = 18, .physical =  0, .count =  7, },
			{ .logical = 25, .physical = 40, .count =  5, },
			{ .logical = 30, .physical =  0, .count = 70, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf1, key);
		test_assert(!err);
		check_seg(res, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf1);
		dleaf2_destroy(btree, leaf2);
		clean_main(sb, btree);
	}
	test_end();
	if (test_start("test05.2")) {
		/* The seg1 end and seg2 start are same logical */
		struct block_segment seg1[] = {
			{ .block = 10, .count =  5, },
			{ .block = 20, .count =  3, },
		};
		dleaf2_set_alloc_seg(seg1, ARRAY_SIZE(seg1));
		key = dleaf2_set_w_req(&rq, 10, 8, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 0, 18, leaf1, key, &hint);
		test_assert(!ret);

		struct block_segment seg2[] = {
			{ .block = 30, .count =  2, },
			{ .block = 40, .count =  5, },
		};
		dleaf2_set_alloc_seg(seg2, ARRAY_SIZE(seg2));
		key = dleaf2_set_w_req(&rq, 18, 7, seg, ARRAY_SIZE(seg));
		ret = dleaf2_write(btree, 18, TUXKEY_LIMIT, leaf2, key, &hint);
		test_assert(!ret);

		/* Test merge */
		ret = dleaf2_merge(btree, leaf1, leaf2);
		test_assert(ret == 1);

		struct test_extent res[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 10, .count =  5, },
			{ .logical = 15, .physical = 20, .count =  3, },
			{ .logical = 18, .physical = 30, .count =  2, },
			{ .logical = 20, .physical = 40, .count =  5, },
			{ .logical = 25, .physical =  0, .count = 75, },
		};
		key = dleaf2_set_r_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf1, key);
		test_assert(!err);
		check_seg(res, 0, seg, rq.seg_cnt);

		dleaf2_destroy(btree, leaf1);
		dleaf2_destroy(btree, leaf2);
		clean_main(sb, btree);
	}
	test_end();

	dleaf2_destroy(btree, leaf1);
	dleaf2_destroy(btree, leaf2);
	clean_main(sb, btree);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 10 };
	init_buffers(dev, 1 << 20, 2);

	int err = tux3_init_mem();
	assert(!err);

	struct sb *sb = rapid_sb(dev);
	sb->super = INIT_DISKSB(dev->bits, 2048);
	setup_sb(sb, &sb->super);

	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	test_init(argv[0]);

	struct inode *inode = rapid_open_inode(sb, NULL, S_IFREG);
	struct btree *btree = &tux_inode(inode)->btree;
	init_btree(&tux_inode(inode)->btree, sb, no_root, dtree_ops());

	/* Set fake backend mark to modify backend objects. */
	tux3_start_backend(sb);

	if (test_start("test01"))
		test01(sb, btree);
	test_end();

	if (test_start("test02"))
		test02(sb, btree);
	test_end();

	if (test_start("test03"))
		test03(sb, btree);
	test_end();

	if (test_start("test04"))
		test04(sb, btree);
	test_end();

	if (test_start("test05"))
		test05(sb, btree);
	test_end();

	tux3_end_backend();

	clean_main(sb, btree);
	return test_failures();
}
