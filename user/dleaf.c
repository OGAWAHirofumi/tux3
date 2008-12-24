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

#include "tux3.h"
#ifndef main
#undef MAX_GROUP_ENTRIES
#define MAX_GROUP_ENTRIES 7
#endif
#include "kernel/dleaf.c"

#ifndef main
block_t balloc(struct sb *sb, unsigned blocks)
{
	return sb->nextalloc += blocks;
}

void bfree(struct sb *sb, block_t block, unsigned blocks)
{
	printf(" free %Lx, count %x\n", (L)block, blocks);
}

struct dleaf *dleaf_create(struct btree *btree)
{
	struct dleaf *leaf = malloc(btree->sb->blocksize);
	dleaf_init(btree, leaf);
	return leaf;
}

void dleaf_destroy(struct btree *btree, struct dleaf *leaf)
{
	assert(dleaf_sniff(btree, leaf));
	free(leaf);
}

void *dleaf_lookup(struct btree *btree, struct dleaf *leaf, tuxkey_t index, unsigned *count)
{
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = groups - dleaf_groups(leaf);
	struct entry *entries = (void *)grbase;
	struct diskextent *extents = leaf->table;
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

static void dwalk_probe_check(struct dwalk *walk, block_t index, struct diskextent *ex)
{
	trace("index %Lx (%Lx)", (L)dwalk_index(walk), (L)index);
	assert(dwalk_index(walk) == index);
	trace("block %Lx, count %x (%Lx, %x)", (L)dwalk_block(walk), dwalk_count(walk), (L)extent_block(*ex), extent_count(*ex));
	assert(dwalk_block(walk) == extent_block(*ex));
	assert(dwalk_count(walk) == extent_count(*ex));
}

int main(int argc, char *argv[])
{
	printf("--- leaf test ---\n");
	struct sb *sb = &(struct sb){ .blocksize = 1 << 10 };
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
		int (*try)(struct dwalk *walk, tuxkey_t key, struct diskextent extent) = i ? dwalk_add: dwalk_mock;
		try(walk, 0x3001001, make_extent(0x1, 1));
		try(walk, 0x3001002, make_extent(0x2, 1));
		try(walk, 0x3001003, make_extent(0x3, 1));
		try(walk, 0x3001004, make_extent(0x4, 1));
		try(walk, 0x3001005, make_extent(0x5, 1));
		try(walk, 0x3001006, make_extent(0x6, 1));
		if (!i) printf("mock free = %i, used = %i\n", walk->mock.free, walk->mock.used);
	}
	assert(!dleaf_check(btree, leaf));
	dleaf_dump(btree, leaf);
	for (int i = 0; i < ARRAY_SIZE(keys); i++) {
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
	assert(!dleaf_check(btree, leaf));
	dleaf_dump(btree, leaf);
	dleaf_chop(btree, 0x14014LL, leaf);
	assert(!dleaf_check(btree, leaf));
	dleaf_dump(btree, leaf);
	dleaf_destroy(btree, leaf);
	dleaf_destroy(btree, dest);

	if (1) {
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
		struct dwalk *walk1 = &(struct dwalk){ };
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		for (int i = 0; i < ARRAY_SIZE(data); i++)
			dwalk_add(walk1, data[i].index, data[i].ex);
		assert(!dleaf_check(btree, leaf1));
		/* dwalk_probe test */
		int i, ret;
		for (i = 0; i < ARRAY_SIZE(data); i++) {
			ret = dwalk_probe(leaf1, sb->blocksize, walk1, data[i].index);
			assert(ret);
			dwalk_probe_check(walk1, data[i].index, &data[i].ex);
		}
		ret = dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		assert(ret);
		dwalk_probe_check(walk1, data[0].index, &data[0].ex);
		ret = dwalk_probe(leaf1, sb->blocksize, walk1, 0x3001000003ULL);
		assert(ret);
		dwalk_probe_check(walk1, data[1].index, &data[1].ex);
		ret = dwalk_probe(leaf1, sb->blocksize, walk1, 0x3001000011ULL);
		assert(ret);
		dwalk_probe_check(walk1, data[2].index, &data[2].ex);
		ret = dwalk_probe(leaf1, sb->blocksize, walk1, 0x3001000015ULL);
		assert(ret);
		dwalk_probe_check(walk1, data[5].index, &data[5].ex);
		ret = dwalk_probe(leaf1, sb->blocksize, walk1, 0x3003000000ULL);
		assert(!ret);
		assert(dwalk_end(walk1));
		/* test for dwalk_next and dwalk_back */
#define NR	7
		struct dwalk w1[NR + 1], w2[NR + 1];
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
	if (1) {
		struct dleaf *leaf1 = dleaf_create(btree);
		struct dwalk *walk1 = &(struct dwalk){ };
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		dwalk_add(walk1, 0x3001000001ULL, make_extent(0x1, 1));
		dwalk_add(walk1, 0x3001000002ULL, make_extent(0x2, 1));
		dwalk_add(walk1, 0x3001000003ULL, make_extent(0x3, 1));
		dwalk_add(walk1, 0x3001000004ULL, make_extent(0x4, 1));
		dwalk_add(walk1, 0x3001000005ULL, make_extent(0x5, 10));
		dwalk_add(walk1, 0x3002000000ULL, make_extent(0xa, 1));
		dwalk_add(walk1, 0x3002000001ULL, make_extent(0xb, 1));
		assert(!dleaf_check(btree, leaf1));
		tuxkey_t k1[NR + 1];
		struct diskextent e1[NR + 1];
		int nr = 0;
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		while (!dwalk_end(walk1)) {
			k1[nr] = dwalk_index(walk1);
			e1[nr] = *walk1->extent;
			nr++;
			dwalk_next(walk1);
		}
		/* dwalk_chop test (dwalk_chop() will use dwalk_back()) */
		dwalk_probe(leaf1, sb->blocksize, walk1, 0x3002000000ULL);
		dwalk_chop(walk1);
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		nr = 0;
		while (!dwalk_end(walk1)) {
			assert(k1[nr] == dwalk_index(walk1));
			assert(extent_block(e1[nr]) == dwalk_block(walk1));
			assert(extent_count(e1[nr]) == dwalk_count(walk1));
			nr++;
			dwalk_next(walk1);
		}
		/* dleaf_chop test */
		dleaf_chop(btree, 0x3001000008ULL, leaf1);
		assert(!dleaf_check(btree, leaf1));
		dwalk_probe(leaf1, sb->blocksize, walk1, 0);
		nr = 0;
		while (!dwalk_end(walk1)) {
			assert(dwalk_index(walk1) == k1[nr]);
			assert(dwalk_block(walk1) == extent_block(e1[nr]));
			if (nr == 4)
				assert(dwalk_count(walk1) == 3);
			else
				assert(dwalk_count(walk1) == extent_count(e1[nr]));
			nr++;
			dwalk_next(walk1);
		}
		assert(nr == 5);
		dleaf_destroy(btree, leaf1);
	}
	return 0;
}
#endif
