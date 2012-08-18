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

#include "tux3user.h"
#include "test.h"

#ifndef trace
#define trace trace_off
#endif

#include "balloc-dummy.c"
#include "kernel/btree.c"

static void clean_main(struct sb *sb, struct inode *inode)
{
	log_finish(sb);
	log_finish_cycle(sb);
	free_map(inode->map);
	destroy_defer_bfree(&sb->derollup);
	destroy_defer_bfree(&sb->defree);
	invalidate_buffers(sb->volmap->map);
	clear_inode(sb->volmap);
	put_super(sb);
}

struct uleaf { u32 magic, count; struct uentry { u16 key, val; } entries[]; };

static inline struct uleaf *to_uleaf(vleaf *leaf)
{
	return leaf;
}

static void uleaf_btree_init(struct btree *btree)
{
	struct sb *sb = btree->sb;
	btree->entries_per_leaf = (sb->blocksize - offsetof(struct uleaf, entries)) / sizeof(struct uentry);
}

static int uleaf_sniff(struct btree *btree, vleaf *leaf)
{
	return to_uleaf(leaf)->magic == 0xc0de;
}

static int uleaf_init(struct btree *btree, vleaf *leaf)
{
	*to_uleaf(leaf) = (struct uleaf){ .magic = 0xc0de };
	return 0;
}

static unsigned uleaf_need(struct btree *btree, vleaf *leaf)
{
	return to_uleaf(leaf)->count;
}

static unsigned uleaf_free(struct btree *btree, vleaf *leaf)
{
	return btree->entries_per_leaf - to_uleaf(leaf)->count;
}

static void uleaf_dump(struct btree *btree, vleaf *data)
{
#if 0
	struct uleaf *leaf = data;
	printf("leaf %p/%i", leaf, leaf->count);
	struct uentry *entry, *limit = leaf->entries + leaf->count;
	for (entry = leaf->entries; entry < limit; entry++)
		printf(" %x:%x", entry->key, entry->val);
	printf(" (%x free)\n", uleaf_free(btree, leaf));
#endif
}

static tuxkey_t uleaf_split(struct btree *btree, tuxkey_t hint, vleaf *from, vleaf *into)
{
	test_assert(uleaf_sniff(btree, from));
	struct uleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && hint > leaf->entries[leaf->count - 1].key) // binsearch!
		at = leaf->count;
	unsigned tail = leaf->count - at;
	uleaf_init(btree, into);
	veccopy(to_uleaf(into)->entries, leaf->entries + at, tail);
	to_uleaf(into)->count = tail;
	leaf->count = at;
	return tail ? to_uleaf(into)->entries[0].key : hint;
}

static unsigned uleaf_seek(struct btree *btree, tuxkey_t key, struct uleaf *leaf)
{
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	return at;
}

static int uleaf_chop(struct btree *btree, tuxkey_t start, u64 len,vleaf *vleaf)
{
	struct uleaf *leaf = vleaf;
	unsigned start_at, stop_at, count;
	tuxkey_t stop;

	/* Chop all range if len >= TUXKEY_LIMIT */
	stop = (len >= TUXKEY_LIMIT) ? TUXKEY_LIMIT : start + len;

	start_at = uleaf_seek(btree, start, leaf);
	stop_at = uleaf_seek(btree, stop, leaf);
	count = leaf->count - stop_at;
	vecmove(&leaf->entries[start_at], &leaf->entries[stop_at], count);
	leaf->count = start_at + count;
	return 1;
}

static void *uleaf_resize(struct btree *btree, tuxkey_t key, vleaf *data, unsigned one)
{
	test_assert(uleaf_sniff(btree, data));
	struct uleaf *leaf = data;
	unsigned at = uleaf_seek(btree, key, leaf);
	if (at < leaf->count && leaf->entries[at].key == key)
		goto out;
	if (uleaf_free(btree, leaf) < one)
		return NULL;
	trace("expand leaf at 0x%x by %i", at, one);
	vecmove(leaf->entries + at + one, leaf->entries + at, leaf->count++ - at);
out:
	return leaf->entries + at;
}

static void uleaf_merge(struct btree *btree, vleaf *vinto, vleaf *vfrom)
{
	struct uleaf *into = vinto;
	struct uleaf *from = vfrom;

	assert(into->count + from->count <= btree->entries_per_leaf);
	vecmove(&into->entries[into->count], from->entries, from->count);
	into->count += from->count;
}

static struct btree_ops ops = {
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

static int uleaf_insert(struct btree *btree, struct uleaf *leaf, unsigned key, unsigned val)
{
	trace("insert 0x%x -> 0x%x", key, val);
	struct uentry *entry = uleaf_resize(btree, key, leaf, 1);
	if (!entry)
		return 1; // need to expand
	test_assert(entry);
	*entry = (struct uentry){ .key = key, .val = val };
	return 0;
}

static struct uentry *uleaf_lookup(struct uleaf *leaf, unsigned key)
{
	unsigned at;

	for (at = 0; at < leaf->count; at++) {
		if (leaf->entries[at].key == key)
			return &leaf->entries[at];
	}
	return NULL;
}

/* Test of new_leaf() and new_node() */
static void test01(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;
	int err;

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	/* ->leaf_init() should be called */
	struct buffer_head *buffer = new_leaf(btree);
	test_assert(uleaf_sniff(btree, bufdata(buffer)));
	/* Test of uleaf_insert() */
	for (int i = 0; i < 7; i++)
		uleaf_insert(btree, bufdata(buffer), i, i + 0x100);
	for (int i = 0; i < 7; i++) {
		struct uentry *uentry = uleaf_lookup(bufdata(buffer), i);
		test_assert(uentry);
		test_assert(uentry->val == i + 0x100);
	}
	/* Test of uleaf_chop() */
	uleaf_chop(btree, 2, 3, bufdata(buffer));
	for (int i = 0; i < 7; i++) {
		struct uentry *uentry = uleaf_lookup(bufdata(buffer), i);
		if (2 <= i && i < 5) {
			test_assert(uentry == NULL);
		} else {
			test_assert(uentry);
			test_assert(uentry->val == i + 0x100);
		}
	}
	mark_buffer_dirty_non(buffer);
	uleaf_dump(btree, bufdata(buffer));
	blockput(buffer);

	clean_main(sb, inode);
}

static void btree_expand_test(struct cursor *cursor, tuxkey_t key)
{
	int err;

	err = btree_probe(cursor, key);
	test_assert(!err);

	struct uentry *entry = btree_expand(cursor, key, 1);
	test_assert(!IS_ERR(entry));

	*entry = (struct uentry){ .key = key, .val = key + 0x100 };
	mark_buffer_dirty_non(cursor_leafbuf(cursor));

	block_t block = bufindex(cursor_leafbuf(cursor));
	release_cursor(cursor);

	/* probe added key: buffer should be same */
	err = btree_probe(cursor, key);
	test_assert(!err);
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	test_assert(block == bufindex(leafbuf));
	entry = uleaf_lookup(bufdata(leafbuf), key);
	test_assert(entry);
	test_assert(entry->key == key);
	release_cursor(cursor);
}

/* btree_expand() and btree_chop() test */
static void test02(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;
	int err;

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	struct cursor *cursor = alloc_cursor(btree, 8); /* +8 for new depth */
	test_assert(cursor);

	/* At least add 1 depth */
	int keys = sb->entries_per_node * btree->entries_per_leaf + 1;
	/* Add keys to test tree_expand() until new depth */
	for (int key = 0; key < keys; key++)
		btree_expand_test(cursor, key);
	test_assert(btree->root.depth == 2);
	/* Check key again after addition completed */
	for (int key = 0; key < keys; key++) {
		test_assert(btree_probe(cursor, key) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		struct uentry *entry = uleaf_lookup(bufdata(leafbuf), key);
		test_assert(entry);
		test_assert(entry->key == key);
		release_cursor(cursor);
	}
	/* Delte all */
	test_assert(btree_chop(btree, 0, TUXKEY_LIMIT) == 0);
	/* btree should have empty root */
	test_assert(btree->root.depth == 1);

	/* btree_probe() should return same path always */
	test_assert(btree_probe(cursor, 0) == 0);
	block_t root = bufindex(cursor->path[0].buffer);
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	release_cursor(cursor);
	for (int key = 0; key < keys; key++) {
		test_assert(btree_probe(cursor, key) == 0);
		test_assert(root == bufindex(cursor->path[0].buffer));
		test_assert(leafbuf == cursor_leafbuf(cursor));
		/* This should be no key in leaf */
		struct uentry *entry = uleaf_lookup(bufdata(leafbuf), key);
		test_assert(entry == NULL);
		release_cursor(cursor);
	}

	free_cursor(cursor);

	clean_main(sb, inode);
}

/* btree_expand() and btree_chop() test (reverse order) */
static void test03(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;
	int err;

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	struct cursor *cursor = alloc_cursor(btree, 8); /* +8 for new depth */
	test_assert(cursor);

	/* Some depths */
	int keys = sb->entries_per_node * btree->entries_per_leaf * 100;

	for (int key = keys - 1; key >= 0; key--)
		btree_expand_test(cursor, key);
	assert(btree->root.depth >= 5); /* this test expects more than 5 */

	/* Check key again after addition completed */
	for (int key = keys - 1; key >= 0; key--) {
		test_assert(btree_probe(cursor, key) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		struct uentry *entry = uleaf_lookup(bufdata(leafbuf), key);
		test_assert(entry);
		test_assert(entry->key == key);
		release_cursor(cursor);
	}
	/* Delete one by one for some keys from end */
	int left = sb->entries_per_node * btree->entries_per_leaf * 80;
	for (int key = keys - 1; key >= left; key--) {
		test_assert(btree_chop(btree, key, TUXKEY_LIMIT) == 0);

		int ret, check = 0;

		test_assert(btree_probe(cursor, check) == 0);
		do {
			struct buffer_head *leafbuf;

			leafbuf = cursor_leafbuf(cursor);
			while (uleaf_lookup(bufdata(leafbuf), check))
				check++;
			ret = cursor_advance(cursor);
			test_assert(ret >= 0);
		} while (ret);
		test_assert(check == key);
		release_cursor(cursor);
	}

	free_cursor(cursor);

	clean_main(sb, inode);
}

static void test04(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;
	int err;

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	/* Insert_node test */
	struct cursor *cursor = alloc_cursor(btree, 1); /* +1 for new depth */
	test_assert(cursor);

	test_assert(!btree_probe(cursor, 0));
	for (int i = 0; i < sb->entries_per_node - 1; i++) {
		struct buffer_head *buffer = new_leaf(btree);
		trace("buffer: index %Lx", (L)buffer->index);
		test_assert(!IS_ERR(buffer));
		mark_buffer_dirty_non(buffer);
		test_assert(btree_insert_leaf(cursor, 100 + i, buffer) == 0);
	}
	release_cursor(cursor);
	/* Insert key=1 after key=0 */
	test_assert(!btree_probe(cursor, 0));
	struct buffer_head *buffer = new_leaf(btree);
	test_assert(!IS_ERR(buffer));
	mark_buffer_dirty_non(buffer);
	test_assert(btree_insert_leaf(cursor, 1, buffer) == 0);
	/* probe same key with cursor2 */
	struct cursor *cursor2 = alloc_cursor(btree, 0);
	test_assert(!btree_probe(cursor2, 1));
	for (int i = 0; i <= cursor->level; i++) {
		test_assert(cursor->path[i].buffer == cursor2->path[i].buffer);
		test_assert(cursor->path[i].next == cursor2->path[i].next);
	}
	release_cursor(cursor);
	release_cursor(cursor2);
	free_cursor(cursor);
	free_cursor(cursor2);
	test_assert(!btree_chop(btree, 0, TUXKEY_LIMIT));

	clean_main(sb, inode);
}

#ifdef ATOMIC
static void clean_test05(struct sb *sb, struct inode *inode,
			 struct cursor *cursor, struct path_level *path)
{
	release_cursor(cursor);
	free_cursor(cursor);
	free(path);

	clean_main(sb, inode);
}

/* Test of cursor_redirect() */
static void test05(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;
	struct path_level *orig;
	int err;

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	init_btree(btree, sb, no_root, &ops);
	err = alloc_empty_btree(btree);
	test_assert(!err);

	struct cursor *cursor = alloc_cursor(btree, 8); /* +8 for new depth */
	test_assert(cursor);

	/* Some depths */
	int keys = sb->entries_per_node * btree->entries_per_leaf * 100;
	for (int key = keys - 1; key >= 0; key--)
		btree_expand_test(cursor, key);
	assert(btree->root.depth >= 5); /* this test expects more than 5 */

	test_assert(btree_probe(cursor, 0) == 0);
	orig = malloc(sizeof(*orig) * (cursor->level + 1));
	memcpy(orig, cursor->path, sizeof(*orig) * (cursor->level + 1));

	if (test_start("test05.1")) {
		/* Redirect full path */
		for (int i = 0; i <= cursor->level; i++) {
			set_buffer_clean(orig[i].buffer);
			get_bh(orig[i].buffer);
		}
		test_assert(cursor_redirect(cursor) == 0);
		for (int i = 0; i <= cursor->level; i++) {
			struct path_level *at = &cursor->path[i];

			/* Modify orignal buffer */
			memset(bufdata(orig[i].buffer), 0, sb->blocksize);
			blockput(orig[i].buffer);

			/* Redirected? */
			test_assert(orig[i].buffer != at->buffer);
			/* If not leaf, check ->next too */
			if (i < cursor->level)
				test_assert(orig[i].next != at->next);
		}
		release_cursor(cursor);

		/* Check key */
		for (int key = 0; key < keys; key++) {
			struct buffer_head *leafbuf;
			struct uentry *entry;

			test_assert(btree_probe(cursor, key) == 0);
			leafbuf = cursor_leafbuf(cursor);
			entry = uleaf_lookup(bufdata(leafbuf), key);
			test_assert(entry);
			test_assert(entry->key == key);
			release_cursor(cursor);
		}

		clean_test05(sb, inode, cursor, orig);
	}
	test_end();

	if (test_start("test05.2")) {
		/* Redirect partial path */
		for (int i = cursor->level / 2; i <= cursor->level ; i++) {
			set_buffer_clean(orig[i].buffer);
			get_bh(orig[i].buffer);
		}
		test_assert(cursor_redirect(cursor) == 0);
		for (int i = 0; i <= cursor->level; i++) {
			struct path_level *at = &cursor->path[i];

			/* Redirected? */
			if (i < cursor->level / 2) {
				test_assert(orig[i].buffer == at->buffer);
				test_assert(orig[i].next == at->next);
				continue;
			}

			/* Modify orignal buffer */
			memset(bufdata(orig[i].buffer), 0, sb->blocksize);
			blockput(orig[i].buffer);

			test_assert(orig[i].buffer != at->buffer);
			/* If not leaf, check ->next too */
			if (i < cursor->level)
				test_assert(orig[i].next != at->next);
		}
		release_cursor(cursor);

		/* Check key */
		for (int key = 0; key < keys; key++) {
			struct buffer_head *leafbuf;
			struct uentry *entry;

			test_assert(btree_probe(cursor, key) == 0);

			leafbuf = cursor_leafbuf(cursor);
			entry = uleaf_lookup(bufdata(leafbuf), key);
			test_assert(entry);
			test_assert(entry->key == key);
			release_cursor(cursor);
		}

		clean_test05(sb, inode, cursor, orig);
	}
	test_end();

	clean_test05(sb, inode, cursor, orig);
}
#else
/* Of course, redirect doesn't work on writeback */
static void test05(struct sb *sb, struct inode *inode)
{
}
#endif /* !ATOMIC */

/* btree_chop() range chop (and adjust_parent_sep()) test */
static void test06(struct sb *sb, struct inode *inode)
{
	struct btree *btree = &tux_inode(inode)->btree;

	init_btree(btree, sb, no_root, &ops);

	/*
	 * Test below:
	 *
	 *         +----- (0, 8)---------+
	 *         |                     |
	 *    + (..., 2, 5) +        + (8, 12) +
	 *    |        |    |        |         |
	 * (dummy)   (3,4) (6,7)   (10,11)    (13,14)
	 *
	 * Make above tree and chop (7 - 10), then btree_chop() merges
	 * (6) and (11). And adjust_parent_sep() adjust (0,8) to (0,12).
	 *
	 * [(dummy) is to prevent merge nodes of (2,5) and (8,12)]
	 */

	/* Create leaves */
	struct buffer_head *leaf[4];
	int leaf_key[] = { 3, 6, 10, 13, };
	for (int i = 0; i < ARRAY_SIZE(leaf); i++) {
		leaf[i] = new_leaf(btree);
		test_assert(uleaf_sniff(btree, bufdata(leaf[i])));
		for (int j = leaf_key[i]; j < leaf_key[i] + 2; j++)
			uleaf_insert(btree, bufdata(leaf[i]), j, j + 0x100);
	}

	/* Create nodes */
	struct buffer_head *node[3];
	/* [left key, right key, left child, right child] */
	int node_key[3][4] = {
		{ 0, 8, 0, 0, }, /* child pointer is filled later */
		{ 2, 5, bufindex(leaf[0]), bufindex(leaf[1]), },
		{ 8, 12, bufindex(leaf[2]), bufindex(leaf[3]), },
	};
	for (int i = 0; i < ARRAY_SIZE(node); i++) {
		node[i] = new_node(btree);
		for (int j = 0; j < 2; j++) {
			struct bnode *bnode = bufdata(node[i]);
			struct index_entry *p = bnode->entries;
			bnode_add_index(bnode, p + j, node_key[i][2 + j],
					node_key[i][j]);
		}
	}
	/* fill node with dummy to prevent merge */
	for (int i = 0; i < sb->entries_per_node - 2; i++) {
		struct bnode *bnode = bufdata(node[1]);
		bnode_add_index(bnode, bnode->entries, 0, 100);
	}

	/* Fill child pointer in root node */
	struct bnode *root = bufdata(node[0]);
	root->entries[0].block = to_be_u64(bufindex(node[1]));
	root->entries[1].block = to_be_u64(bufindex(node[2]));
	/* Set root node to btree */
	btree->root = (struct root){ .block = bufindex(node[0]), .depth = 2 };

	for(int i = 0; i < ARRAY_SIZE(leaf); i++) {
		mark_buffer_dirty_non(leaf[i]);
		blockput(leaf[i]);
	}
	for(int i = 0; i < ARRAY_SIZE(node); i++) {
		mark_buffer_rollup_non(node[i]);
		blockput(node[i]);
	}

	struct cursor *cursor = alloc_cursor(btree, 8); /* +8 for new depth */
	test_assert(cursor);

	/* Check keys */
	for (int i = 0; i < ARRAY_SIZE(leaf_key); i++) {
		test_assert(btree_probe(cursor, leaf_key[i]) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		for (int j = 0; j < 2; j++) {
			struct uentry *entry;
			entry = uleaf_lookup(bufdata(leafbuf), leaf_key[i] + j);
			test_assert(entry);
			test_assert(entry->key == leaf_key[i] + j);
		}
		release_cursor(cursor);
	}

	/* Chop (7 - 10) and check again */
	test_assert(btree_chop(btree, 7, 4) == 0);
	/* Check if adjust_parent_sep() changed key from 8 to 12 */
	test_assert(cursor_read_root(cursor) == 0);
	root = bufdata(cursor->path[cursor->level].buffer);
	test_assert(from_be_u64(root->entries[1].key) == 12);
	release_cursor(cursor);

	for (int i = 0; i < ARRAY_SIZE(leaf_key); i++) {
		test_assert(btree_probe(cursor, leaf_key[i]) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		for (int j = 0; j < 2; j++) {
			struct uentry *entry;
			entry = uleaf_lookup(bufdata(leafbuf), leaf_key[i] + j);
			if (7 <= leaf_key[i] + j && leaf_key[i] + j <= 10) {
				test_assert(entry == NULL);
			} else {
				test_assert(entry);
				test_assert(entry->key == leaf_key[i] + j);
			}
		}
		release_cursor(cursor);
	}

	free_cursor(cursor);

	clean_main(sb, inode);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 6 };
	init_buffers(dev, 1 << 20, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, 1024);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	struct inode *inode = rapid_open_inode(sb, dev_errio, 0);
	assert(inode);

	test_init(argv[0]);

	if (test_start("test01"))
		test01(sb, inode);
	test_end();

	if (test_start("test02"))
		test02(sb, inode);
	test_end();

	if (test_start("test03"))
		test03(sb, inode);
	test_end();

	if (test_start("test04"))
		test04(sb, inode);
	test_end();

	if (test_start("test05"))
		test05(sb, inode);
	test_end();

	if (test_start("test06"))
		test06(sb, inode);
	test_end();

	clean_main(sb, inode);

	return test_failures();
}
