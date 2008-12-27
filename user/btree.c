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

static void uleaf_btree_init(struct btree *btree)
{
	struct sb *sb = btree->sb;
	btree->entries_per_leaf = (sb->blocksize - offsetof(struct uleaf, entries)) / sizeof(struct entry);
}

int uleaf_sniff(struct btree *btree, vleaf *leaf)
{
	return to_uleaf(leaf)->magic == 0xc0de;
}

int uleaf_init(struct btree *btree, vleaf *leaf)
{
	*to_uleaf(leaf) = (struct uleaf){ .magic = 0xc0de };
	return 0;
}

unsigned uleaf_need(struct btree *btree, vleaf *leaf)
{
	return to_uleaf(leaf)->count;
}

unsigned uleaf_free(struct btree *btree, vleaf *leaf)
{
	return btree->entries_per_leaf - to_uleaf(leaf)->count;
}

void uleaf_dump(struct btree *btree, vleaf *data)
{
	struct uleaf *leaf = data;
	printf("leaf %p/%i", leaf, leaf->count);
	struct uentry *entry, *limit = leaf->entries + leaf->count;
	for (entry = leaf->entries; entry < limit; entry++)
		printf(" %x:%x", entry->key, entry->val);
	printf(" (%x free)\n", uleaf_free(btree, leaf));
}

tuxkey_t uleaf_split(struct btree *btree, tuxkey_t key, vleaf *from, vleaf *into)
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

unsigned uleaf_seek(struct btree *btree, tuxkey_t key, struct uleaf *leaf)
{
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	return at;
}

int uleaf_chop(struct btree *btree, tuxkey_t key, vleaf *vleaf)
{
	struct uleaf *leaf = vleaf;
	unsigned at = uleaf_seek(btree, key, leaf);
	leaf->count = at;
	return 1;
}

void *uleaf_resize(struct btree *btree, tuxkey_t key, vleaf *data, unsigned one)
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

void uleaf_merge(struct btree *btree, vleaf *into, vleaf *from)
{
}

struct btree_ops ops = {
	.btree_init = uleaf_btree_init,
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
	.bfree = bfree,
};

block_t balloc(struct sb *sb, unsigned blocks)
{
	printf("-> %Lx\n", (L)sb->nextalloc);
	return sb->nextalloc += blocks;
}

void bfree(struct sb *sb, block_t block, unsigned blocks)
{
	printf("free %Lx, count %x\n", (L)block, blocks);
}

int uleaf_insert(struct btree *btree, struct uleaf *leaf, unsigned key, unsigned val)
{
	printf("insert 0x%x -> 0x%x\n", key, val);
	struct uentry *entry = uleaf_resize(btree, key, leaf, 1);
	if (!entry)
		return 1; // need to expand
	assert(entry);
	*entry = (struct uentry){ .key = key, .val = val };
	return 0;
}

static void tree_expand_test(struct cursor *cursor, tuxkey_t key)
{
	struct btree *btree = cursor->btree;
	if (probe(btree, key, cursor))
		error("probe for %Lx failed", (L)key);
	struct uentry *entry = tree_expand(btree, key, 1, cursor);
	*entry = (struct uentry){ .key = key, .val = key + 0x100 };
	mark_buffer_dirty(cursor_leafbuf(cursor));
	block_t block = bufindex(cursor_leafbuf(cursor));
	release_cursor(cursor);

	/* probe added key: buffer should be same */
	if (probe(btree, key, cursor))
		error("probe for %Lx failed", (L)key);
	assert(block == bufindex(cursor_leafbuf(cursor)));
	release_cursor(cursor);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 6 };
	map_t *map = new_map(dev, NULL);
	struct sb *sb = &(struct sb){ .devmap = map, .blocksize = 1 << dev->bits };
	map->inode = &(struct inode){ .i_sb = sb, .map = map };
	init_buffers(dev, 1 << 20);
	sb->entries_per_node = (sb->blocksize - offsetof(struct bnode, entries)) / sizeof(struct index_entry);
	printf("entries_per_node = %i\n", sb->entries_per_node);
	struct btree btree = { };
	assert(!new_btree(&btree, sb, &ops));

	if (0) {
		struct buffer_head *buffer = new_leaf(&btree);
		for (int i = 0; i < 7; i++)
			uleaf_insert(&btree, bufdata(buffer), i, i + 0x100);
		mark_buffer_dirty(buffer);
		uleaf_dump(&btree, bufdata(buffer));
		exit(0);
	}

	/* tree_expand() test, and reverse order */
	struct cursor *cursor = alloc_cursor(&btree, 1); /* +1 for new depth */
	int until_new_depth = sb->entries_per_node * btree.entries_per_leaf + 1;
	for (int key = 0; key < until_new_depth; key++)
		tree_expand_test(cursor, key);
	show_tree_range(&btree, 0, -1);
	tree_chop(&btree, &(struct delete_info){ .key = 0 }, 0);

	for (int key = until_new_depth * 100; key >= 0; key -= 100)
		tree_expand_test(cursor, key);
	show_tree_range(&btree, 0, -1);
	free_cursor(cursor);
	tree_chop(&btree, &(struct delete_info){ .key = 0 }, 0);

	/* insert_node test */
	cursor = alloc_cursor(&btree, 1); /* +1 for new depth */
	assert(!probe(&btree, 0, cursor));
	for (int i = 0; i < sb->entries_per_node - 1; i++) {
		struct buffer_head *buffer = new_leaf(&btree);
		assert(buffer);
		level_pop_brelse(cursor);
		level_push(cursor, buffer, NULL);
		insert_node(&btree, 100 + i, bufindex(buffer), cursor);
	}
	release_cursor(cursor);
	/* insert key=1 after key=0 */
	assert(!probe(&btree, 0, cursor));
	struct buffer_head *buffer = new_leaf(&btree);
	level_pop_brelse(cursor);
	level_push(cursor, buffer, NULL);
	insert_node(&btree, 1, bufindex(buffer), cursor);
	/* probe same key with cursor2 */
	struct cursor *cursor2 = alloc_cursor(&btree, 0);
	assert(!probe(&btree, 1, cursor2));
	for (int i = 0; i < cursor->len; i++) {
		assert(cursor->path[i].buffer == cursor2->path[i].buffer);
		assert(cursor->path[i].next == cursor2->path[i].next);
	}
	release_cursor(cursor);
	release_cursor(cursor2);
	free_cursor(cursor);
	free_cursor(cursor2);
	tree_chop(&btree, &(struct delete_info){ .key = 0 }, 0);
	exit(0);
}
#endif
