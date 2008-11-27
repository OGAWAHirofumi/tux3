/*
 * Generic btree operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "diskio.h"

#ifndef trace
#define trace trace_off
#endif

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/btree.c"

#ifndef main
struct uleaf { u32 magic, count; struct uentry { u16 key, val; } entries[]; };

static inline struct uleaf *to_uleaf(vleaf *leaf)
{
	return leaf;
}

int uleaf_sniff(BTREE, vleaf *leaf)
{
	return to_uleaf(leaf)->magic == 0xc0de;
}

int uleaf_init(BTREE, vleaf *leaf)
{
	*to_uleaf(leaf) = (struct uleaf){ .magic = 0xc0de };
	return 0;
}

unsigned uleaf_need(BTREE, vleaf *leaf)
{
	return to_uleaf(leaf)->count;
}

unsigned uleaf_free(BTREE, vleaf *leaf)
{
	return btree->entries_per_leaf - to_uleaf(leaf)->count;
}

void uleaf_dump(BTREE, vleaf *data)
{
	struct uleaf *leaf = data;
	printf("leaf %p/%i", leaf, leaf->count);
	struct uentry *entry, *limit = leaf->entries + leaf->count;
	for (entry = leaf->entries; entry < limit; entry++)
		printf(" %x:%x", entry->key, entry->val);
	printf(" (%x free)\n", uleaf_free(btree, leaf));
}

tuxkey_t uleaf_split(BTREE, tuxkey_t key, vleaf *from, vleaf *into)
{
	assert(uleaf_sniff(btree, from));
	struct uleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && key > leaf->entries[leaf->count - 1].key) // binsearch!
		at = leaf->count;
	unsigned tail = leaf->count - at;
	uleaf_init(btree, into);
	veccopy(to_uleaf(into)->entries, leaf->entries + at, tail);
	to_uleaf(into)->count = tail;
	leaf->count = at;
	return at < leaf->count ? to_uleaf(into)->entries[0].key : key;
}

unsigned uleaf_seek(BTREE, tuxkey_t key, struct uleaf *leaf)
{
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	return at;
}

int uleaf_chop(BTREE, tuxkey_t key, vleaf *vleaf)
{
	struct uleaf *leaf = vleaf;
	unsigned at = uleaf_seek(btree, key, leaf);
	leaf->count = at;
	return 0;
}

void *uleaf_resize(BTREE, tuxkey_t key, vleaf *data, unsigned one)
{
	assert(uleaf_sniff(btree, data));
	struct uleaf *leaf = data;
	if (uleaf_free(btree, leaf) < one)
		return NULL;
	unsigned at = uleaf_seek(btree, key, leaf);
	printf("expand leaf at 0x%x by %i\n", at, one);
	vecmove(leaf->entries + at + one, leaf->entries + at, leaf->count++ - at);
	return leaf->entries + at;
}

void uleaf_merge(BTREE, vleaf *into, vleaf *from)
{
}

struct btree_ops ops = {
	.leaf_sniff = uleaf_sniff,
	.leaf_init = uleaf_init,
	.leaf_split = uleaf_split,
	.leaf_resize = uleaf_resize,
	.leaf_dump = uleaf_dump,
	.leaf_need = uleaf_need,
	.leaf_free = uleaf_free,
	.leaf_merge = uleaf_merge,
	.leaf_chop = uleaf_chop,
	.balloc = balloc,
};

block_t balloc(SB)
{
	printf("-> %Lx\n", (L)sb->nextalloc);
	return sb->nextalloc++;
}

int uleaf_insert(BTREE, struct uleaf *leaf, unsigned key, unsigned val)
{
	printf("insert 0x%x -> 0x%x\n", key, val);
	struct uentry *entry = uleaf_resize(btree, key, leaf, 1);
	if (!entry)
		return 1; // need to expand
	assert(entry);
	*entry = (struct uentry){ .key = key, .val = val };
	return 0;
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 6 };
	map_t *map = new_map(dev, NULL);
	SB = &(struct sb){ .devmap = map, .blocksize = 1 << dev->bits };
	map->inode = &(struct inode){ .i_sb = sb, .map = map };
	init_buffers(dev, 1 << 20);
	sb->entries_per_node = (sb->blocksize - offsetof(struct bnode, entries)) / sizeof(struct index_entry);
	printf("entries_per_node = %i\n", sb->entries_per_node);
	struct btree btree = new_btree(sb, &ops);
	btree.entries_per_leaf = (sb->blocksize - offsetof(struct uleaf, entries)) / sizeof(struct entry);

	if (0) {
		struct buffer_head *buffer = new_leaf(&btree);
		for (int i = 0; i < 7; i++)
			uleaf_insert(&btree, bufdata(buffer), i, i + 0x100);
		mark_buffer_dirty(buffer);
		uleaf_dump(&btree, bufdata(buffer));
		exit(0);
	}

	struct cursor cursor[30];
	for (int key = 0; key < 30; key++) {
		if (probe(&btree, key, cursor))
			error("probe for %i failed", key);
		struct uentry *entry = tree_expand(&btree, key, 1, cursor);
		*entry = (struct uentry){ .key = key, .val = key + 0x100 };
		mark_buffer_dirty(cursor[btree.root.depth].buffer);
		release_cursor(cursor, btree.root.depth + 1);
	}
	show_tree_range(&btree, 0, -1);
	show_buffers(sb->devmap);
	tree_chop(&btree, &(struct delete_info){ .key = 0x10 }, -1);
	show_tree_range(&btree, 0, -1);
	exit(0);
}
#endif
