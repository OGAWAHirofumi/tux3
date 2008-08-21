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
#include <errno.h>
#include "diskio.h"
#include "buffer.h"
#include "tux3.h"

#define main notmain
#include "btree.c"
#undef main

struct vleaf { u32 magic, count; struct entry { u32 key; struct btree btree; } entries[]; };

static inline struct vleaf *to_vleaf(vleaf *leaf)
{
	return leaf;
}

int vleaf_sniff(SB, vleaf *leaf)
{
	return to_vleaf(leaf)->magic == 0x2008;
}

int vleaf_init(SB, vleaf *leaf)
{
	*to_vleaf(leaf) = (struct vleaf){ .magic = 0x2008 };
	return 0;
}

unsigned vleaf_need(SB, vleaf *leaf)
{
	return to_vleaf(leaf)->count;
}

unsigned vleaf_free(SB, vleaf *leaf)
{
	unsigned max_entries = (struct entry *)(leaf + sb->blocksize) - to_vleaf(leaf)->entries;
	return max_entries - to_vleaf(leaf)->count;
}

void vleaf_dump(SB, vleaf *data)
{
	struct vleaf *leaf = data;
	printf("leaf %p/%i", leaf, leaf->count);
	struct entry *limit = leaf->entries + leaf->count;
	for (struct entry *entry = leaf->entries; entry < limit; entry++)
		printf(" %x@%Li/%u", entry->key, (L)entry->btree.root, entry->btree.levels);
	printf(" (%x free)\n", vleaf_free(sb, leaf));
}

tuxkey_t vleaf_split(SB, vleaf *from, vleaf *into, tuxkey_t key)
{
	assert(vleaf_sniff(sb, from));
	struct vleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && key > leaf->entries[leaf->count - 1].key) // binsearch!
		at = leaf->count;
	unsigned tail = leaf->count - at;
	vleaf_init(sb, into);
	veccopy(to_vleaf(into)->entries, leaf->entries + at, tail);
	to_vleaf(into)->count = tail;
	leaf->count = at;
	return at < leaf->count ? to_vleaf(into)->entries[0].key : key;
}

void *vleaf_expand(SB, vleaf *data, tuxkey_t key, unsigned more)
{
	assert(vleaf_sniff(sb, data));
	struct vleaf *leaf = data;
	if (vleaf_free(sb, leaf) < more)
		return NULL;
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	//printf("expand leaf at 0x%x by %i\n", at, more);
	vecmove(leaf->entries + at + more, leaf->entries + at, leaf->count++ - at);
	return leaf->entries + at;
}

void vleaf_merge(SB, vleaf *into, vleaf *from)
{
}

struct btree_ops ops = {
	.leaf_sniff = vleaf_sniff,
	.leaf_init = vleaf_init,
	.leaf_split = vleaf_split,
	.leaf_expand = vleaf_expand,
	.leaf_dump = vleaf_dump,
	.leaf_need = vleaf_need,
	.leaf_free = vleaf_free,
	.leaf_merge = vleaf_merge,
	.balloc = balloc,
};

block_t balloc(SB)
{
	return sb->nextalloc++;
}

int vleaf_insert(SB, struct vleaf *leaf, unsigned key, struct btree *btree)
{
	printf("insert 0x%x: 0x%Lx/%i\n", key, btree->root, btree->levels);
	struct entry *entry = vleaf_expand(sb, leaf, key, 1);
	if (!entry)
		return 1; // need to expand
	assert(entry);
	*entry = (struct entry){ .key = key, .btree = *btree };
	return 0;
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 7 };
	struct map *map = new_map(dev, NULL);
	SB = &(struct sb){ .devmap = map, .blocksize = 1 << dev->bits };
	map->inode = &(struct inode){ .sb = sb, .map = map };
	init_buffers(dev, 1 << 20);
	sb->entries_per_node = (sb->blocksize - offsetof(struct bnode, entries)) / sizeof(struct index_entry);
	printf("entries_per_node = %i\n", sb->entries_per_node);

	if (0) {
		struct buffer *buffer = new_leaf(sb, &ops);
		for (int key = 0; key < 7; key++)
			vleaf_insert(sb, buffer->data, key, &(struct btree){ key + 0x100, 1 });
		vleaf_dump(sb, buffer->data);
		return 0;
	}

	struct btree btree = new_btree(sb, &ops);
	struct path path[30];
	btree.entries_per_leaf = (sb->blocksize - offsetof(struct vleaf, entries)) / sizeof(struct entry);

	for (int key = 0; key < 10; key++) {
		if (probe(sb, &btree, key, path, &ops))
			error("probe for %i failed", key);
		struct entry *entry = tree_expand(sb, &btree, key, 1, path, &ops);
		*entry = (struct entry){ .key = key, .btree = { key + 0x100, 1 } };
		release_path(path, btree.levels + 1);
	}
	show_tree_range(sb, &ops, &btree, 0, -1);
	show_buffers(map);
	return 0;
}
