/*
 * Inode table btree leaf operations
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
#define trace trace_off
#endif

#include "kernel/ileaf.c"

static struct ileaf *ileaf_create(struct btree *btree)
{
	struct ileaf *leaf = malloc(btree->sb->blocksize);
	assert(leaf);
	btree->ops->leaf_init(btree, leaf);
	return leaf;
}

static void ileaf_destroy(struct btree *btree, struct ileaf *leaf)
{
	assert(ileaf_sniff(btree, leaf));
	free(leaf);
}

static void test_append(struct btree *btree, struct ileaf *leaf, inum_t inum, int more, char fill)
{
	unsigned size = 0;
	char *attrs = ileaf_lookup(btree, inum, leaf, &size);
	attrs = ileaf_resize(btree, inum, leaf, size + more);
	memset(attrs + size, fill, more);
}

static void test_remove(struct btree *btree, struct ileaf *leaf, inum_t inum, int less)
{
	unsigned size = 0;
	char *attrs = ileaf_lookup(btree, inum, leaf, &size);
	printf("attrs %p, attrs size = %i\n", attrs, size);
	attrs = ileaf_resize(btree, inum, leaf, size - less);
}

struct ileaf_data {
	inum_t inum;
	int size;
	unsigned char c;
	unsigned char buf[32];
};

static void check_ileaf_with_data(struct btree *btree, struct ileaf *ileaf,
				  struct ileaf_data *data, int nr_data)
{
	for (int i = 0; i < nr_data; i++) {
		void *attrs;
		unsigned size;
		attrs = ileaf_lookup(btree, data[i].inum, ileaf, &size);
		if (data[i].size == 0)
			test_assert(attrs == NULL);
		else {
			test_assert(attrs);
			test_assert(size == data[i].size);
			test_assert(!memcmp(data[i].buf, attrs, data[i].size));
		}
	}
}


/* Test basic ileaf operations */
static void test01(struct sb *sb, struct btree *btree)
{

	struct ileaf *leaf = ileaf_create(btree);
	struct ileaf *dest = ileaf_create(btree);
	void *attrs;
	unsigned size, more;

	struct ileaf_data data[] = {
		{ .inum = 0x10, .size = 0, .c = 'n', },
		{ .inum = 0x13, .size = 2, .c = 'a', },
		{ .inum = 0x14, .size = 4, .c = 'b', },
		{ .inum = 0x16, .size = 6, .c = 'c', },
		{ .inum = 0x18, .size = 0, .c = 'y', },
	};

	/* Init data[] */
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		memset(data[i].buf, data[i].c, data[i].size);

	leaf->ibase = to_be_u64(0x10);
	/* Add data */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		if (data[i].size == 0)
			continue;
		test_append(btree, leaf, data[i].inum, data[i].size, data[i].c);
	}
	/* Check */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	/* Split leaf */
	inum_t dest_base = ileaf_split(btree, 0x10, leaf, dest);
	test_assert(dest_base == 0x11);
	/* Check leaf and dest */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		attrs = ileaf_lookup(btree, data[i].inum, leaf, &size);
		test_assert(attrs == NULL);
		test_assert(size == 0);
	}
	check_ileaf_with_data(btree, dest, &data[1], ARRAY_SIZE(data) - 1);

	/* Merge leaf and dest */
	ileaf_merge(btree, leaf, dest);
	/* Check leaf */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	/* Change attribute */
	more = 2;
	memset(data[0].buf + data[0].size, 'x', more);
	data[0].size += more;
	test_append(btree, leaf, data[0].inum, more, 'x');
	/* Check */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	/* Add new inode */
	more = 3;
	memset(data[4].buf, data[4].c, more);
	data[4].size += more;
	test_append(btree, leaf, data[4].inum, more, data[4].c);
	/* Check */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	/* Shrink attribute */
	more = 5;
	data[3].size -= more;
	test_remove(btree, leaf, data[3].inum, more);
	/* Check */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	/* Test find_empty_inode() */
	for (int i = 0x11; i <= 0x20; i++) {
		inum_t alloc = find_empty_inode(btree, leaf, i);

		inum_t expected = i;
		for (int j = 0; j < ARRAY_SIZE(data); j++) {
			if (expected == data[j].inum)
				expected++;
		}

		test_assert(alloc == expected);
	}

	/* Remove inode */
	data[2].size = 0;
	ileaf_purge(btree, data[2].inum, leaf);
	data[4].size = 0;
	ileaf_purge(btree, data[4].inum, leaf);
	/* Check */
	check_ileaf_with_data(btree, leaf, data, ARRAY_SIZE(data));

	test_assert(ileaf_check(btree, leaf) == 0);

	ileaf_destroy(btree, leaf);
	ileaf_destroy(btree, dest);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 12 };
	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	struct btree btree;
	init_btree(&btree, sb, no_root, &itable_ops);

	test_init(argv[0]);

	if (test_start("test01"))
		test01(sb, &btree);
	test_end();

	return test_failures();
}
