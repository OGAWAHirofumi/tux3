/*
 * File index btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "hexdump.c"
#include "trace.h"

#ifndef trace
#define trace trace_on
#endif

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/dleaf.c"

#ifndef main
block_t balloc(SB)
{
	return sb->nextalloc++;
}

void bfree(SB, block_t block)
{
	printf(" free %Lx\n", (L)block);
}

struct dleaf *dleaf_create(BTREE)
{
	struct dleaf *leaf = malloc(btree->sb->blocksize);
	dleaf_init(btree, leaf);
	return leaf;
}

void dleaf_destroy(BTREE, struct dleaf *leaf)
{
	assert(dleaf_sniff(btree, leaf));
	free(leaf);
}

void *dleaf_lookup(BTREE, struct dleaf *leaf, tuxkey_t index, unsigned *count)
{
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = groups - dleaf_groups(leaf);
	struct entry *entries = (void *)grbase;
	struct extent *extents = leaf->table;
	unsigned keylo = index & 0xffffff, keyhi = index >> 24;

	for (struct group *group = groups - 1; group >= grbase; group--) {
		struct entry *enbase = entries - group_count(group);
		if (keyhi == group_keyhi(group))
			for (struct entry *entry = entries; entry > enbase;)
				if (entry_keylo(--entry) == keylo) {
					unsigned offset = entry - enbase == group_count(group) - 1 ? 0 : entry_limit(entry + 1);
					*count = entry_limit(entry) - offset;
					return extents + offset;
				}
		/* could fail out early here */
		extents += entry_limit(enbase);
		entries -= group_count(group);
	}
	*count = 0;
	return NULL;
}

int main(int argc, char *argv[])
{
	printf("--- leaf test ---\n");
	SB = &(struct sb){ .blocksize = 1 << 10 };
	struct btree *btree = &(struct btree){ .sb = sb, .ops = &dtree_ops };
	struct dleaf *leaf = dleaf_create(btree);
	dleaf_chop(btree, 0x14014LL, leaf);

	unsigned hi = 1 << 24, hi2 = 3 * hi/*, next = 0*/;
	unsigned keys[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, hi + 0x44, hi + 0x99 };
	struct dwalk *walk = &(struct dwalk){ };

	for (int i = 1; i < 2; i++) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x3000055);
		if ((walk->mock.groups = dleaf_groups(walk->leaf))) {
			walk->mock.group = *walk->group;
			walk->mock.entry = *walk->entry;
		}
		int (*try)(struct dwalk *walk, tuxkey_t key, struct extent extent) = i ? dwalk_pack: dwalk_mock;
		try(walk, 0x3001001, make_extent(0x1, 1));
		try(walk, 0x3001002, make_extent(0x2, 1));
		try(walk, 0x3001003, make_extent(0x3, 1));
		try(walk, 0x3001004, make_extent(0x4, 1));
		try(walk, 0x3001005, make_extent(0x5, 1));
		try(walk, 0x3001006, make_extent(0x6, 1));
		if (!i) printf("mock free = %i, used = %i\n", walk->mock.free, walk->mock.used);
	}
	dleaf_dump(btree, leaf);
	dleaf_check(btree, leaf);

	if (1) {
		/* test for dwalk_next and dwalk_back */
		struct dleaf *leaf1 = dleaf_create(btree);
		struct dwalk *walk1 = &(struct dwalk){ };
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		dwalk_pack(walk1, 0x3001000001ULL, make_extent(0x1, 1));
		dwalk_pack(walk1, 0x3001000002ULL, make_extent(0x2, 1));
		dwalk_pack(walk1, 0x3001000003ULL, make_extent(0x3, 1));
		dwalk_pack(walk1, 0x3001000004ULL, make_extent(0x4, 1));
		dwalk_pack(walk1, 0x3001000005ULL, make_extent(0x5, 1));
		dwalk_pack(walk1, 0x3002000000ULL, make_extent(0xa, 1));
		dwalk_pack(walk1, 0x3002000001ULL, make_extent(0xb, 1));
#define NR	7
		struct dwalk w1[NR + 1], w2[NR + 1];
		int i;
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		for (i = 0; i < NR; i++) {
			w1[i] = *walk1;
			dwalk_next(walk1);
		}
		for (i = NR - 1; i >= 0; i--) {
			dwalk_back(walk1);
			w2[i] = *walk1;
		}
		for (i = 0; i < NR; i++)
			assert(memcmp(&w2[i], &w2[i], sizeof(w1[0])) == 0);
		dleaf_destroy(btree, leaf1);
	}
	exit(0);
	if (1) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x1000044);
		dwalk_back(walk);
		dwalk_back(walk);
		for (struct extent *extent; (extent = dwalk_next(walk));)
			printf("0x%Lx => 0x%Lx\n", (L)dwalk_index(walk), (L)extent_block(*extent));
		exit(0);
	}
	if (1) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x1c01c);
		dwalk_chop(walk);
		dleaf_dump(btree, leaf);
		exit(0);
	}
	dleaf_dump(btree, leaf);
	for (int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		unsigned key = keys[i];
		unsigned count;
		void *found = dleaf_lookup(btree, leaf, key, &count);
		if (count) {
			printf("lookup 0x%x, found [%i] ", key, count );
			hexdump(found, count);
		} else
			printf("0x%x not found\n", key);
	}

	struct dleaf *dest = dleaf_create(btree);
	tuxkey_t key = dleaf_split(btree, 0, leaf, dest);
	printf("split key 0x%Lx\n", (L)key);
	dleaf_dump(btree, leaf);
	dleaf_dump(btree, dest);
	dleaf_merge(btree, leaf, dest);
	dleaf_dump(btree, leaf);
	dleaf_chop(btree, 0x14014LL, leaf);
	dleaf_dump(btree, leaf);
	dleaf_destroy(btree, leaf);
	dleaf_destroy(btree, dest);
	exit(0);
}
#endif
