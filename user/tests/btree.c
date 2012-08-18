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

static void clean_main(struct sb *sb, struct inode *inode)
{
	log_finish(sb);
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

static tuxkey_t uleaf_split(struct btree *btree, tuxkey_t key, vleaf *from, vleaf *into)
{
	test_assert(uleaf_sniff(btree, from));
	struct uleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && key > leaf->entries[leaf->count - 1].key) // binsearch!
		at = leaf->count;
	unsigned tail = leaf->count - at;
	uleaf_init(btree, into);
	veccopy(to_uleaf(into)->entries, leaf->entries + at, tail);
	to_uleaf(into)->count = tail;
	leaf->count = at;
	return tail ? to_uleaf(into)->entries[0].key : key;
}

static unsigned uleaf_seek(struct btree *btree, tuxkey_t key, struct uleaf *leaf)
{
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	return at;
}

static int uleaf_chop(struct btree *btree, tuxkey_t key, vleaf *vleaf)
{
	struct uleaf *leaf = vleaf;
	unsigned at = uleaf_seek(btree, key, leaf);
	leaf->count = at;
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

static void uleaf_merge(struct btree *btree, vleaf *into, vleaf *from)
{
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
	for (int i = 0; i < 7; i++)
		uleaf_insert(btree, bufdata(buffer), i, i + 0x100);
	mark_buffer_dirty_non(buffer);
	uleaf_dump(btree, bufdata(buffer));
	blockput(buffer);

	clean_main(sb, inode);
}

static void tree_expand_test(struct cursor *cursor, tuxkey_t key)
{
	int err;

	err = probe(cursor, key);
	test_assert(!err);

	struct uentry *entry = tree_expand(cursor, key, 1);
	test_assert(!IS_ERR(entry));

	*entry = (struct uentry){ .key = key, .val = key + 0x100 };
	mark_buffer_dirty_non(cursor_leafbuf(cursor));

	block_t block = bufindex(cursor_leafbuf(cursor));
	release_cursor(cursor);

	/* probe added key: buffer should be same */
	err = probe(cursor, key);
	test_assert(!err);
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	test_assert(block == bufindex(leafbuf));
	entry = uleaf_lookup(bufdata(leafbuf), key);
	test_assert(entry);
	test_assert(entry->key == key);
	release_cursor(cursor);
}

/* tree_expand() and tree_chop() test */
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
		tree_expand_test(cursor, key);
	test_assert(btree->root.depth == 2);
	/* Check key again after addition completed */
	for (int key = 0; key < keys; key++) {
		test_assert(probe(cursor, key) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		struct uentry *entry = uleaf_lookup(bufdata(leafbuf), key);
		test_assert(entry);
		test_assert(entry->key == key);
		release_cursor(cursor);
	}
	/* Delte all */
	{
		struct delete_info info = { .key = 0 };
		test_assert(tree_chop(btree, &info, 0) == 0);
	}
	/* btree should have empty root */
	test_assert(btree->root.depth == 1);
	/* probe() should return same path always */
	test_assert(probe(cursor, 0) == 0);
	block_t root = bufindex(cursor->path[0].buffer);
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	release_cursor(cursor);
	for (int key = 0; key < keys; key++) {
		test_assert(probe(cursor, key) == 0);
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

/* tree_expand() and tree_chop() test (reverse order) */
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
		tree_expand_test(cursor, key);
	assert(btree->root.depth >= 5); /* this test expects more than 5 */

	/* Check key again after addition completed */
	for (int key = keys - 1; key >= 0; key--) {
		test_assert(probe(cursor, key) == 0);
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		struct uentry *entry = uleaf_lookup(bufdata(leafbuf), key);
		test_assert(entry);
		test_assert(entry->key == key);
		release_cursor(cursor);
	}
	/* Delete one by one for some keys from end */
	int left = sb->entries_per_node * btree->entries_per_leaf * 80;
	for (int key = keys - 1; key >= left; key--) {
		struct delete_info info = { .key = key };
		test_assert(tree_chop(btree, &info, 0) == 0);

		int ret, check = 0;

		test_assert(probe(cursor, check) == 0);
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

	test_assert(!probe(cursor, 0));
	for (int i = 0; i < sb->entries_per_node - 1; i++) {
		struct buffer_head *buffer = new_leaf(btree);
		trace("buffer: index %Lx", (L)buffer->index);
		test_assert(!IS_ERR(buffer));
		mark_buffer_dirty_non(buffer);
		test_assert(btree_insert_leaf(cursor, 100 + i, buffer) == 0);
	}
	release_cursor(cursor);
	/* Insert key=1 after key=0 */
	test_assert(!probe(cursor, 0));
	struct buffer_head *buffer = new_leaf(btree);
	test_assert(!IS_ERR(buffer));
	mark_buffer_dirty_non(buffer);
	test_assert(btree_insert_leaf(cursor, 1, buffer) == 0);
	/* probe same key with cursor2 */
	struct cursor *cursor2 = alloc_cursor(btree, 0);
	test_assert(!probe(cursor2, 1));
	for (int i = 0; i < cursor->len; i++) {
		test_assert(cursor->path[i].buffer == cursor2->path[i].buffer);
		test_assert(cursor->path[i].next == cursor2->path[i].next);
	}
	release_cursor(cursor);
	release_cursor(cursor2);
	free_cursor(cursor);
	free_cursor(cursor2);
	test_assert(!tree_chop(btree, &(struct delete_info){ .key = 0 }, 0));

	clean_main(sb, inode);
}

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
		tree_expand_test(cursor, key);
	assert(btree->root.depth >= 5); /* this test expects more than 5 */

	test_assert(probe(cursor, 0) == 0);
	orig = malloc(sizeof(*orig) * cursor->len);
	memcpy(orig, cursor->path, sizeof(*orig) * cursor->len);

	if (test_start("test05.1")) {
		/* Redirect full path */
		for (int i = 0; i < cursor->len; i++) {
			set_buffer_clean(orig[i].buffer);
			get_bh(orig[i].buffer);
		}
		test_assert(cursor_redirect(cursor) == 0);
		for (int i = 0; i < cursor->len; i++) {
			struct path_level *at = &cursor->path[i];

			/* Modify orignal buffer */
			memset(bufdata(orig[i].buffer), 0, sb->blocksize);
			blockput(orig[i].buffer);

			/* Redirected? */
			test_assert(orig[i].buffer != at->buffer);
			/* If not leaf, check ->next too */
			if (i < cursor->len - 1)
				test_assert(orig[i].next != at->next);
		}
		release_cursor(cursor);

		/* Check key */
		for (int key = 0; key < keys; key++) {
			struct buffer_head *leafbuf;
			struct uentry *entry;

			test_assert(probe(cursor, key) == 0);
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
		for (int i = cursor->len / 2; i < cursor->len ; i++) {
			set_buffer_clean(orig[i].buffer);
			get_bh(orig[i].buffer);
		}
		test_assert(cursor_redirect(cursor) == 0);
		for (int i = 0; i < cursor->len; i++) {
			struct path_level *at = &cursor->path[i];

			/* Redirected? */
			if (i < cursor->len / 2) {
				test_assert(orig[i].buffer == at->buffer);
				test_assert(orig[i].next == at->next);
				continue;
			}

			/* Modify orignal buffer */
			memset(bufdata(orig[i].buffer), 0, sb->blocksize);
			blockput(orig[i].buffer);

			test_assert(orig[i].buffer != at->buffer);
			/* If not leaf, check ->next too */
			if (i < cursor->len - 1)
				test_assert(orig[i].next != at->next);
		}
		release_cursor(cursor);

		/* Check key */
		for (int key = 0; key < keys; key++) {
			struct buffer_head *leafbuf;
			struct uentry *entry;

			test_assert(probe(cursor, key) == 0);

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

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 6 };
	init_buffers(dev, 1 << 20, 1);

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

	clean_main(sb, inode);

	return test_failures();
}
