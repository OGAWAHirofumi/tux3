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

#ifndef trace
#define trace trace_off
#endif

#include "kernel/ileaf.c"

static struct ileaf *ileaf_create(struct btree *btree)
{
	struct ileaf *leaf = malloc(btree->sb->blocksize);
	ileaf_init(btree, leaf);
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
	printf("attrs %p, attrs size = %i\n", attrs, size);
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

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 12 };
	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	printf("--- test inode table leaf methods ---\n");
	struct btree *btree = &(struct btree){
		.sb = sb,
		.ops = &itable_ops,
		.entries_per_leaf = 64, // !!! should depend on blocksize
	};
	struct ileaf *leaf = ileaf_create(btree);
	struct ileaf *dest = ileaf_create(btree);
	leaf->ibase = to_be_u64(0x10);
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x13, 2, 'a');
	test_append(btree, leaf, 0x14, 4, 'b');
	test_append(btree, leaf, 0x16, 6, 'c');
	ileaf_dump(btree, leaf);
	ileaf_split(btree, 0x10, leaf, dest);
	ileaf_dump(btree, leaf);
	ileaf_dump(btree, dest);
	ileaf_merge(btree, leaf, dest);
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x13, 3, 'x');
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x18, 3, 'y');
	ileaf_dump(btree, leaf);
	test_remove(btree, leaf, 0x16, 5);
	ileaf_dump(btree, leaf);
	unsigned size = 0;
	char *inode = ileaf_lookup(btree, 0x13, leaf, &size);
	hexdump(inode, size);
	for (int i = 0x11; i <= 0x20; i++)
		printf("goal 0x%x => 0x%Lx\n", i, (L)find_empty_inode(btree, leaf, i));
	ileaf_purge(btree, 0x14, leaf);
	ileaf_purge(btree, 0x18, leaf);
	ileaf_check(btree, leaf);
	ileaf_dump(btree, leaf);
	ileaf_destroy(btree, leaf);
	ileaf_destroy(btree, dest);
	exit(0);
}
