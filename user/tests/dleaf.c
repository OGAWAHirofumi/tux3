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

#undef MAX_GROUP_ENTRIES
#define MAX_GROUP_ENTRIES 7
#include "kernel/dleaf.c"

static void clean_main(struct sb *sb)
{
	log_finish(sb);
	log_finish_cycle(sb);
	destroy_defer_bfree(&sb->derollup);
	destroy_defer_bfree(&sb->defree);
	put_super(sb);
}

static struct dleaf *dleaf_create(struct btree *btree)
{
	struct dleaf *leaf = malloc(btree->sb->blocksize);
	if (leaf)
		btree->ops->leaf_init(btree, leaf);
	return leaf;
}

static void dleaf_destroy(struct btree *btree, struct dleaf *leaf)
{
	assert(btree->ops->leaf_sniff(btree, leaf));
	free(leaf);
}

#define dwalk_probe_check(walk, index, ex) do {			\
	test_assert(dwalk_index(walk) == index);		\
	test_assert(dwalk_block(walk) == extent_block(ex));	\
	test_assert(dwalk_count(walk) == extent_count(ex));	\
} while (0)

/* Test basic operations */
static void test01(struct sb *sb, struct btree *btree)
{
	unsigned blocksize = sb->blocksize;
	struct dwalk *walk = &(struct dwalk){ };
	struct dleaf *leaf1, *leaf2;
	int ret;

	leaf1 = dleaf_create(btree);

	/* chop empty dleaf */
	ret = dleaf_chop(btree, 0x14014ULL, TUXKEY_LIMIT, leaf1);
	test_assert(ret == 0);

	struct {
		block_t index;
		struct diskextent ex;
	} data[] = {
		{ 0x3001001ULL, make_extent(0x1, 1), },
		{ 0x3001002ULL, make_extent(0x2, 5), },
		{ 0x4001003ULL, make_extent(0x3, 1), },
		{ 0x4001004ULL, make_extent(0x4, 1), },
		{ 0x4001005ULL, make_extent(0x5, 1), },
		{ 0x5001006ULL, make_extent(0x6, 1), },
	};

	/* Add extents */
	ret = dwalk_probe(leaf1, blocksize, walk, 0x14014ULL);
	test_assert(ret == 0);
	test_assert(dwalk_end(walk));
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_add(walk, data[i].index, data[i].ex);
		test_assert(ret == 0);
	}
	/* Check added extents */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf1, blocksize, walk, data[i].index);
		test_assert(ret == 1);
		dwalk_probe_check(walk, data[i].index, data[i].ex);
	}

	/* Split leaf */
	leaf2 = dleaf_create(btree);

	int pos = ARRAY_SIZE(data) / 2;
	tuxkey_t key = dleaf_split(btree, 0, leaf1, leaf2);
	test_assert(key == data[pos].index);
	/* Check leaves */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf1, blocksize, walk, data[i].index);
		if (i < pos) {
			test_assert(ret == 1);
			dwalk_probe_check(walk, data[i].index, data[i].ex);
		} else
			test_assert(ret == 0);
	}
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf2, blocksize, walk, data[i].index);
		if (i >= pos) {
			test_assert(ret == 1);
			dwalk_probe_check(walk, data[i].index, data[i].ex);
		} else {
			test_assert(ret == 1);
			dwalk_probe_check(walk, data[pos].index, data[pos].ex);
		}
	}

	/* Merge leaf */
	ret = dleaf_merge(btree, leaf1, leaf2);
	test_assert(ret == 1);
	/* Check extents */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf1, blocksize, walk, data[i].index);
		test_assert(ret == 1);
		dwalk_probe_check(walk, data[i].index, data[i].ex);
	}

	/* Chop extents */
	dleaf_chop(btree, data[3].index, TUXKEY_LIMIT, leaf1);
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf1, blocksize, walk, data[i].index);
		if (i < 3) {
			test_assert(ret == 1);
			dwalk_probe_check(walk, data[i].index, data[i].ex);
		} else
			test_assert(ret == 0);
	}

	dleaf_destroy(btree, leaf1);
	dleaf_destroy(btree, leaf2);
	clean_main(sb);
}

/*
 * Test dleaf_merge().
 * (This try to merge the group which exceed MAX_GROUP_ENTRIES.)
 */
static void test02(struct sb *sb, struct btree *btree)
{
	unsigned blocksize = sb->blocksize;

	for (int chop = 1; chop < MAX_GROUP_ENTRIES + 1; chop++) {
		struct dwalk *walk = &(struct dwalk){ };

		struct dleaf *leaf1 = dleaf_create(btree);
		dwalk_probe(leaf1, blocksize, walk, 0);
		for (int i = 0; i < MAX_GROUP_ENTRIES; i++)
			dwalk_add(walk, i, make_extent(10+i, 1));

		struct dleaf *leaf2 = dleaf_create(btree);
		dwalk_probe(leaf2, blocksize, walk, 0);
		for (int i = 0; i < MAX_GROUP_ENTRIES; i++)
			dwalk_add(walk, 100+i, make_extent(100+i, 1));

		/* chop some extents */
		dwalk_probe(leaf1, blocksize, walk, 0);
		for (int i = 0; i < chop; i++)
			dwalk_next(walk);
		dwalk_chop(walk);

		/* merge leaf1 and leaf2 */
		int ret = dleaf_merge(btree, leaf1, leaf2);
		test_assert(ret == 1);

		dwalk_probe(leaf1, blocksize, walk, 0);
		for (int i = 0; i < chop; i++) {
			dwalk_probe_check(walk, i, make_extent(10+i, 1));
			dwalk_next(walk);
		}
		for (int i = 0; i < MAX_GROUP_ENTRIES; i++) {
			dwalk_probe_check(walk, 100+i, make_extent(100+i, 1));
			dwalk_next(walk);
		}
		test_assert(dwalk_end(walk));

		dleaf_destroy(btree, leaf1);
		dleaf_destroy(btree, leaf2);
	}

	clean_main(sb);
}

/*
 * Test dleaf_chop().
 */
static void test03(struct sb *sb, struct btree *btree)
{
	unsigned blocksize = sb->blocksize;
	int ret;

	struct dwalk *walk = &(struct dwalk){ };

	struct {
		block_t index;
		struct diskextent ex;
	} data[] = {
		{ 0x3001000001ULL, make_extent(0x1, 1), },
		{ 0x3001000002ULL, make_extent(0x2, 1), },
		{ 0x3001000003ULL, make_extent(0x3, 1), },
		{ 0x3001000004ULL, make_extent(0x4, 1), },
		{ 0x3001000005ULL, make_extent(0x5, 10), },
		{ 0x3002000000ULL, make_extent(0xa, 1), },
		{ 0x3002000001ULL, make_extent(0xb, 1), },
	};

	/* Add extents */
	struct dleaf *leaf1 = dleaf_create(btree);
	ret = dwalk_probe(leaf1, blocksize, walk, 0);
	test_assert(ret == 0);
	test_assert(dwalk_end(walk));
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_add(walk, data[i].index, data[i].ex);
		test_assert(ret == 0);
	}

	/* Test dleaf_chop() */
	ret = dleaf_chop(btree, 0x3001000008ULL, TUXKEY_LIMIT, leaf1);
	test_assert(ret == 1);

	int nr = 0;
	dwalk_probe(leaf1, blocksize, walk, 0);
	while (!dwalk_end(walk)) {
		if (nr == 4) {
			struct diskextent ex;
			ex = make_extent(extent_block(data[nr].ex), 3);
			dwalk_probe_check(walk, data[nr].index, ex);
		} else
			dwalk_probe_check(walk, data[nr].index, data[nr].ex);
		nr++;
		dwalk_next(walk);
	}
	test_assert(nr == 5);

	dleaf_destroy(btree, leaf1);
	clean_main(sb);
}

/* Test dwalk basic and dwalk_copy() */
static void test04(struct sb *sb, struct btree *btree)
{
	unsigned blocksize = sb->blocksize;

	struct dwalk *walk = &(struct dwalk){ };
	struct {
		block_t index;
		struct diskextent ex;
	} data[] = {
		{ 0x3001000001ULL, make_extent(0x1, 1), },
		{ 0x3001000002ULL, make_extent(0x2, 5), },
		{ 0x3001000011ULL, make_extent(0x8, 1), },
		{ 0x3001000012ULL, make_extent(0x9, 1), },
		{ 0x3001000013ULL, make_extent(0xa, 1), },
		{ 0x3002000000ULL, make_extent(0xb, 1), },
		{ 0x3002000001ULL, make_extent(0xc, 1), },
	};

	struct dleaf *leaf1 = dleaf_create(btree);
	dwalk_probe(leaf1, blocksize, walk, 0);
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		dwalk_add(walk, data[i].index, data[i].ex);

	/* dwalk_copy test */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		struct dleaf *leaf2 = dleaf_create(btree);
		dwalk_probe(leaf1, blocksize, walk, data[i].index);
		dwalk_copy(walk, leaf2);
		dwalk_probe(leaf2, blocksize, walk, data[i].index);
		for (int j = i; j < ARRAY_SIZE(data); j++) {
			dwalk_probe_check(walk, data[j].index, data[j].ex);
			dwalk_next(walk);
		}
		dleaf_destroy(btree, leaf2);
	}

	/* dwalk_probe test */
	int i, ret;
	for (i = 0; i < ARRAY_SIZE(data); i++) {
		ret = dwalk_probe(leaf1, blocksize, walk, data[i].index);
		test_assert(ret);
		dwalk_probe_check(walk, data[i].index, data[i].ex);
	}

	ret = dwalk_probe(leaf1, blocksize, walk, 0);
	test_assert(ret);
	dwalk_probe_check(walk, data[0].index, data[0].ex);

	ret = dwalk_probe(leaf1, blocksize, walk, 0x3001000003ULL);
	test_assert(ret);
	dwalk_probe_check(walk, data[1].index, data[1].ex);

	ret = dwalk_probe(leaf1, blocksize, walk, 0x3001000011ULL);
	test_assert(ret);
	dwalk_probe_check(walk, data[2].index, data[2].ex);

	ret = dwalk_probe(leaf1, blocksize, walk, 0x3001000015ULL);
	test_assert(ret);
	dwalk_probe_check(walk, data[5].index, data[5].ex);

	ret = dwalk_probe(leaf1, blocksize, walk, 0x3003000000ULL);
	test_assert(!ret);
	test_assert(dwalk_end(walk));

	/* test for dwalk_next and dwalk_back */
#define NR	7
	struct dwalk w1[NR + 1], w2[NR + 1];
	dwalk_probe(leaf1, blocksize, walk, 0);
	for (i = 0; i < NR; i++) {
		w1[i] = *walk;
		dwalk_next(walk);
	}
	for (i = NR - 1; i >= 0; i--) {
		dwalk_back(walk);
		w2[i] = *walk;
	}
	for (i = 0; i < NR; i++)
		test_assert(memcmp(&w2[i], &w2[i], sizeof(w1[0])) == 0);

	dleaf_destroy(btree, leaf1);
	clean_main(sb);
}

/*
 * Test dwalk_chop().
 * (This try to chop groups too.)
 */
static void test05(struct sb *sb, struct btree *btree)
{
	unsigned blocksize = sb->blocksize;

	struct dwalk *walk = &(struct dwalk){ };
	struct {
		block_t index;
		struct diskextent ex;
	} data[] = {
		{ 0x0000000000ULL, make_extent(0xc2, 0x40), },
		{ 0x0000800000ULL, make_extent(0x42, 0x40), },
		{ 0x0000800040ULL, make_extent(0x82, 0x40), },
		{ 0x0001100000ULL, make_extent(0x100, 0x40), },
		{ 0x3001000013ULL, make_extent(0x200, 0x40), },
		{ 0x3002000000ULL, make_extent(0x300, 0x40), },
		{ 0x3002000001ULL, make_extent(0x400, 0x40), },
	};

	struct dleaf *leaf1 = dleaf_create(btree);
	dwalk_probe(leaf1, blocksize, walk, 0);
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		dwalk_add(walk, data[i].index, data[i].ex);

	for (int i = ARRAY_SIZE(data) - 1; i >= 0; i--) {
		dwalk_probe(leaf1, blocksize, walk, data[i].index);
		dwalk_chop(walk);
		dwalk_probe(leaf1, blocksize, walk, 0);
		int nr = 0;
		while (!dwalk_end(walk)) {
			dwalk_probe_check(walk, data[nr].index, data[nr].ex);
			nr++;
			dwalk_next(walk);
		}
		test_assert(nr == i);
	}

	dleaf_destroy(btree, leaf1);
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
	init_btree(&btree, sb, no_root, &dtree1_ops);

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
