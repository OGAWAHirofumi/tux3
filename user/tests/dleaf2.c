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

#include "balloc-dummy.c"

#include "kernel/dleaf2.c"

static void clean_main(struct sb *sb)
{
	log_finish(sb);
	log_finish_cycle(sb);
	destroy_defer_bfree(&sb->derollup);
	destroy_defer_bfree(&sb->defree);
	put_super(sb);
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
			struct seg *seg, int nr_segs)
{
	for (int i = 0; i < nr_segs; i++) {
		test_assert(res[i].logical == index);
		test_assert(res[i].physical == seg[i].block);
		test_assert(res[i].count == seg[i].count);
		index += seg[i].count;
	}
}
#define check_seg(_res, _index, _seg, _nr_segs) do {	\
	if (test_assert(_nr_segs == ARRAY_SIZE(_res)))	\
		break;					\
	__check_seg(_res, _index, _seg, _nr_segs);	\
} while (0)

static struct btree_key_range *
dleaf2_set_req(struct dleaf_req *rq, block_t index, unsigned count,
	       struct seg *seg, unsigned max_segs)
{
	rq->key.start = index;
	rq->key.len = count;
	rq->nr_segs = 0;
	rq->max_segs = max_segs;
	rq->seg = seg;

	return &rq->key;
}

/* Test dleaf2_{read,write} operations */
static void test01(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct seg seg[10];
	tuxkey_t hint;
	int err;

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
	 */
	struct seg seg1[] = {
		{ .block = 10, .count = 7, },
		{ .block = 20, .count = 5, },
		{ .block = 30, .count = 3, },
		{ .block = 40, .count = 2, },
		{ .block = 50, .count = 5, },
	};
	key = dleaf2_set_req(&rq, 3, 22, seg1, ARRAY_SIZE(seg1));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(!err);

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
	key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.nr_segs);

	/* Read from middle of extent */
	struct test_extent res3[] = {
		{ .logical = 13, .physical = 23, .count =  2, },
		{ .logical = 15, .physical = 30, .count =  3, },
		{ .logical = 18, .physical = 40, .count =  2, },
		{ .logical = 20, .physical = 50, .count =  3, },
	};
	key = dleaf2_set_req(&rq, 13, 10, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res3, 13, seg, rq.nr_segs);

	if (test_start("test01.1")) {
		/* Overwrite from 0 */
		struct seg seg2[] = {
			{ .block = 110, .count = 5, },
			{ .block = 120, .count = 5, },
		};
		key = dleaf2_set_req(&rq, 3, 10, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.2")) {
		/* Overwrite same logical address */
		struct seg seg2[] = {
			{ .block = 120, .count = 5, },
			{ .block = 130, .count = 3, },
		};
		key = dleaf2_set_req(&rq, 10, 8, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical = 120, .count =  5, },
			{ .logical = 15, .physical = 130, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.3")) {
		/* Overwrite middle of logical address */
		struct seg seg2[] = {
			{ .block = 120, .count = 4, },
			{ .block = 130, .count = 5, },
			{ .block = 140, .count = 2, },
			{ .block = 150, .count = 3, },
		};
		key = dleaf2_set_req(&rq, 8, 14, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.4")) {
		/* Overwrite end of logical address */
		struct seg seg2[] = {
			{ .block = 130, .count = 3, },
			{ .block = 140, .count = 5, },
		};
		key = dleaf2_set_req(&rq, 17, 8, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  2, },
			{ .logical = 17, .physical = 130, .count =  3, },
			{ .logical = 20, .physical = 140, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.5")) {
		/* Overwrite beyond end of logical address */
		struct seg seg2[] = {
			{ .block = 140, .count = 4, },
			{ .block = 150, .count = 7, },
		};
		key = dleaf2_set_req(&rq, 19, 11, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.6")) {
		/* Overwrite at logical address for sentinel */
		struct seg seg2[] = {
			{ .block = 160, .count = 7, },
		};
		key = dleaf2_set_req(&rq, 25, 7, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.7")) {
		/* Overwrite outside of logical address */
		struct seg seg2[] = {
			{ .block = 160, .count = 7, },
		};
		key = dleaf2_set_req(&rq, 33, 7, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.8")) {
		/* Overwrite split range */
		struct seg seg2[] = {
			{ .block = 110, .count = 1, },
		};
		key = dleaf2_set_req(&rq, 5, 1, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.9")) {
		/* Overwrite from before minimum logical address */
		struct seg seg2[] = {
			{ .block = 110, .count = 8, },
			{ .block = 120, .count = 5, },
		};
		key = dleaf2_set_req(&rq, 0, 13, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

		struct test_extent res2[] = {
			{ .logical =  0, .physical = 110, .count =  8, },
			{ .logical =  8, .physical = 120, .count =  5, },
			{ .logical = 13, .physical =  23, .count =  2, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.a")) {
		/* Overwrite from less than minimum logical to minimum */
		struct seg seg2[] = {
			{ .block = 110, .count = 3, },
		};
		key = dleaf2_set_req(&rq, 0, 3, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

		struct test_extent res2[] = {
			{ .logical =  0, .physical = 110, .count =  3, },
			{ .logical =  3, .physical =  10, .count =  7, },
			{ .logical = 10, .physical =  20, .count =  5, },
			{ .logical = 15, .physical =  30, .count =  3, },
			{ .logical = 18, .physical =  40, .count =  2, },
			{ .logical = 20, .physical =  50, .count =  5, },
			{ .logical = 25, .physical =   0, .count = 75, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.b")) {
		/* Overwrite only before minimum logical address */
		struct seg seg2[] = {
			{ .block = 110, .count = 2, },
		};
		key = dleaf2_set_req(&rq, 0, 2, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test01.c")) {
		/* Overwrite all */
		struct seg seg2[] = {
			{ .block = 110, .count = 29, },
		};
		key = dleaf2_set_req(&rq, 1, 29, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =   0, .count =  1, },
			{ .logical =  1, .physical = 110, .count = 29, },
			{ .logical = 30, .physical =   0, .count = 70, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();

	dleaf2_destroy(btree, leaf);
	clean_main(sb);
}

/* Test dleaf2_write in the case of no space in leaf */
static void test02(struct sb *sb, struct btree *btree)
{
#define BASE	0x1000
	struct dleaf2 *leaf;
	struct dleaf_req rq;
	struct btree_key_range *key;
	tuxkey_t hint;
	int err;

	leaf = dleaf2_create(btree);
	assert(leaf);

	/* Make full dleaf (-2 is for hole from 0 and sentinel) */
	for (int i = 0; i < btree->entries_per_leaf - 2; i++) {
		struct seg seg[] = {
			{ .block = 0x100 + i, .count = 1, },
		};
		key = dleaf2_set_req(&rq, BASE + i, 1, seg, ARRAY_SIZE(seg));
		err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
		test_assert(!err);
	}

	/* Can't write at all */
	struct seg seg1[] = {
		{ .block = 0x200, .count = 1, },
	};
	key = dleaf2_set_req(&rq, 0x100000, 1, seg1, ARRAY_SIZE(seg1));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(err == -ENOSPC);
	test_assert(rq.nr_segs == 0);

	/* Can't overwrite at all */
	struct seg seg2[] = {
		{ .block = 0x200, .count = 1, },
	};
	key = dleaf2_set_req(&rq, BASE / 2, 1, seg2, ARRAY_SIZE(seg2));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(err == -ENOSPC);
	test_assert(rq.nr_segs == 0);

	/* Can write partially */
	struct seg seg3[] = {
		{ .block = 0x200, .count = 2, },
		{ .block = 0x300, .count = 1, },
		{ .block = 0x301, .count = 1, },
	};
	tuxkey_t index = BASE + (btree->entries_per_leaf - 2 - seg3[0].count);
	key = dleaf2_set_req(&rq, index, 4, seg3, ARRAY_SIZE(seg3));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(err == -ENOSPC);
	test_assert(rq.nr_segs == 1);

	/* Check temporary hole by made in seg3[] */
	struct seg seg4[10];
	unsigned written = seg3[0].count;
	struct test_extent res1[] = {
		{ .logical = index, .physical = 0x200, .count = written, },
		/* temporary hole */
		{ .logical = index + written, .physical = 0, .count = 2, },
	};
	key = dleaf2_set_req(&rq, index, 4, seg4, ARRAY_SIZE(seg4));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res1, index, seg4, rq.nr_segs);

	dleaf2_destroy(btree, leaf);
	clean_main(sb);
}

/* Test dleaf2_chop operation */
static void test03(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct seg seg[10];
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
	struct seg seg1[] = {
		{ .block = 20, .count =  5, },
		{ .block =  0, .count =  3, },
		{ .block = 40, .count =  2, },
		{ .block = 50, .count =  5, },
	};
	key = dleaf2_set_req(&rq, 10, 15, seg1, ARRAY_SIZE(seg1));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf, key, &hint);
	test_assert(!err);

	struct test_extent res1[] = {
		{ .logical =  0, .physical =  0, .count = 10, },
		{ .logical = 10, .physical = 20, .count =  5, },
		{ .logical = 15, .physical =  0, .count =  3, },
		{ .logical = 18, .physical = 40, .count =  2, },
		{ .logical = 20, .physical = 50, .count =  5, },
		{ .logical = 25, .physical =  0, .count = 75, },
	};
	key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.nr_segs);

	if (test_start("test03.1")) {
		/* Chop at middle of logical addresses */
		ret = dleaf2_chop(btree, 13, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical =  0, .physical =  0, .count = 10, },
			{ .logical = 10, .physical = 20, .count =  3, },
			{ .logical = 13, .physical =  0, .count = 87, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();
	if (test_start("test03.4")) {
		/* Chop at before minimum */
		ret = dleaf2_chop(btree, 5, TUXKEY_LIMIT, leaf);
		test_assert(ret == 1);

		struct test_extent res2[] = {
			{ .logical = 0, .physical = 0, .count = 100, },
		};
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf, key);
		test_assert(!err);
		check_seg(res2, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf);
		clean_main(sb);
	}
	test_end();

	dleaf2_destroy(btree, leaf);
	clean_main(sb);
}

/* Test dleaf2_split operations */
static void test04(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf1, *leaf2;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct seg seg[10];
	tuxkey_t hint, newkey;
	int err;

	leaf1 = dleaf2_create(btree);
	assert(leaf1);
	leaf2 = dleaf2_create(btree);
	assert(leaf2);

	/*
	 * base    :          |--------+-----+--+-------|
	 *           0        10      15    18  20      25
	 */
	struct seg seg1[] = {
		{ .block = 10, .count =  5, },
		{ .block = 20, .count =  3, },
		{ .block = 30, .count =  2, },
		{ .block = 40, .count =  5, },
	};
	key = dleaf2_set_req(&rq, 10, 15, seg1, ARRAY_SIZE(seg1));
	err = dleaf2_write(btree, 0, TUXKEY_LIMIT, leaf1, key, &hint);
	test_assert(!err);

	/* Test split */
	newkey = dleaf2_split(btree, 18, leaf1, leaf2);
	test_assert(newkey == 18);	/* current choose is 18 */

	struct test_extent res1[] = {
		{ .logical =  0, .physical =  0, .count = 10, },
		{ .logical = 10, .physical = 10, .count =  5, },
		{ .logical = 15, .physical = 20, .count =  3, },
	};
	key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, 0, newkey, leaf1, key);
	test_assert(!err);
	check_seg(res1, 0, seg, rq.nr_segs);

	struct test_extent res2[] = {
		{ .logical = 18, .physical = 30, .count =  2, },
		{ .logical = 20, .physical = 40, .count =  5, },
		{ .logical = 25, .physical =  0, .count = 75, },
	};
	key = dleaf2_set_req(&rq, newkey, 100 - newkey, seg, ARRAY_SIZE(seg));
	err = dleaf2_read(btree, newkey, TUXKEY_LIMIT, leaf2, key);
	test_assert(!err);
	check_seg(res2, newkey, seg, rq.nr_segs);

	dleaf2_destroy(btree, leaf1);
	dleaf2_destroy(btree, leaf2);
	clean_main(sb);
}

/* Test dleaf2_merge operations */
static void test05(struct sb *sb, struct btree *btree)
{
	struct dleaf2 *leaf1, *leaf2;
	struct dleaf_req rq;
	struct btree_key_range *key;
	struct seg seg[10];
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
		struct seg seg1[] = {
			{ .block = 10, .count =  5, },
			{ .block = 20, .count =  3, },
		};
		key = dleaf2_set_req(&rq, 10, 8, seg1, ARRAY_SIZE(seg1));
		err = dleaf2_write(btree, 0, 18, leaf1, key, &hint);
		test_assert(!err);

		struct seg seg2[] = {
			{ .block =  0, .count =  5, },
			{ .block = 40, .count =  5, },
		};
		key = dleaf2_set_req(&rq, 20, 10, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 20, TUXKEY_LIMIT, leaf2, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf1, key);
		test_assert(!err);
		check_seg(res, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf1);
		dleaf2_destroy(btree, leaf2);
		clean_main(sb);
	}
	test_end();
	if (test_start("test05.2")) {
		/* The seg1 end and seg2 start are same logical */
		struct seg seg1[] = {
			{ .block = 10, .count =  5, },
			{ .block = 20, .count =  3, },
		};
		key = dleaf2_set_req(&rq, 10, 8, seg1, ARRAY_SIZE(seg1));
		err = dleaf2_write(btree, 0, 18, leaf1, key, &hint);
		test_assert(!err);

		struct seg seg2[] = {
			{ .block = 30, .count =  2, },
			{ .block = 40, .count =  5, },
		};
		key = dleaf2_set_req(&rq, 18, 7, seg2, ARRAY_SIZE(seg2));
		err = dleaf2_write(btree, 18, TUXKEY_LIMIT, leaf2, key, &hint);
		test_assert(!err);

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
		key = dleaf2_set_req(&rq, 0, 100, seg, ARRAY_SIZE(seg));
		err = dleaf2_read(btree, 0, TUXKEY_LIMIT, leaf1, key);
		test_assert(!err);
		check_seg(res, 0, seg, rq.nr_segs);

		dleaf2_destroy(btree, leaf1);
		dleaf2_destroy(btree, leaf2);
		clean_main(sb);
	}
	test_end();

	dleaf2_destroy(btree, leaf1);
	dleaf2_destroy(btree, leaf2);
	clean_main(sb);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 10 };
	init_buffers(dev, 1 << 20, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	test_init(argv[0]);

	struct btree btree;
	init_btree(&btree, sb, no_root, &dtree2_ops);

	if (test_start("test01"))
		test01(sb, &btree);
	test_end();

	if (test_start("test02"))
		test02(sb, &btree);
	test_end();

	if (test_start("test03"))
		test03(sb, &btree);
	test_end();

	if (test_start("test04"))
		test04(sb, &btree);
	test_end();

	if (test_start("test05"))
		test05(sb, &btree);
	test_end();

	clean_main(sb);
	return test_failures();
}
