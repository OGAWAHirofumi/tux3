/*
 * Generic btree operations.
 *
 * Copyright (c) 2008-2014 Daniel Phillips
 * Copyright (c) 2008-2014 OGAWA Hirofumi
 */

#include "tux3.h"

#ifndef trace
#define trace trace_off
#endif

/* This value is special case to tell btree doesn't have root yet. */
struct root no_root = {
	.block	= 0,
	.depth	= 0,
};

struct bnode {
	__be16 magic;
	__be16 unused;
	__be32 count;
	struct index_entry {
		__be64 key;
		__be64 block;
	} entries[];
};

/*
 * Note that the first key of an index block is never accessed.  This is
 * because for a btree, there is always one more key than nodes in each
 * index node.  In other words, keys lie between node pointers.  I
 * micro-optimize by placing the node count in the first key, which allows
 * a node to contain an esthetically pleasing binary number of pointers.
 * (Not done yet.)
 */

unsigned calc_entries_per_node(unsigned blocksize)
{
	return (blocksize - sizeof(struct bnode)) / sizeof(struct index_entry);
}

static inline unsigned bcount(struct bnode *node)
{
	return be32_to_cpu(node->count);
}

static struct buffer_head *new_block(struct btree *btree)
{
	block_t block;

	block = balloc_one(btree->sb);
	if (block < 0)
		return ERR_PTR(block);
	struct buffer_head *buffer = vol_getblk(btree->sb, block);
	if (!buffer)
		return ERR_PTR(-ENOMEM); // ERR_PTR me!!! and bfree?
	return buffer;
}

struct buffer_head *new_leaf(struct btree *btree)
{
	struct buffer_head *buffer = new_block(btree);

	if (!IS_ERR(buffer)) {
		memset(bufdata(buffer), 0, bufsize(buffer));
		(btree->ops->leaf_init)(btree, bufdata(buffer));
		mark_buffer_dirty_atomic(buffer);
	}
	return buffer;
}

static inline void bnode_buffer_init(struct buffer_head *buffer)
{
	struct bnode *bnode = bufdata(buffer);
	memset(bnode, 0, bufsize(buffer));
	bnode->magic = cpu_to_be16(TUX3_MAGIC_BNODE);
}

static inline int bnode_sniff(struct bnode *bnode)
{
	if (bnode->magic != cpu_to_be16(TUX3_MAGIC_BNODE))
		return -1;
	return 0;
}

static struct buffer_head *new_node(struct btree *btree)
{
	struct buffer_head *buffer = new_block(btree);

	if (!IS_ERR(buffer)) {
		bnode_buffer_init(buffer);
		mark_buffer_unify_atomic(buffer);
	}
	return buffer;
}

/*
 * A btree cursor has n entries for a btree of depth n, with the first n - 1
 * entries pointing at internal nodes and entry n pointing at a leaf.
 * The next field points at the next index entry that will be loaded in a left
 * to right tree traversal, not the current entry.  The next pointer is null
 * for the leaf, which has its own specialized traversal algorithms.
 */

static inline struct bnode *level_node(struct cursor *cursor, int level)
{
	return bufdata(cursor->path[level].buffer);
}

#ifdef CURSOR_DEBUG
static void cursor_check(struct cursor *cursor)
{
	block_t block = cursor->btree->root.block;
	tuxkey_t key = 0;
	int i;

	for (i = 0; i <= cursor->level; i++) {
		assert(bufindex(cursor->path[i].buffer) == block);
		if (i == cursor->level)
			break;

		struct bnode *bnode = level_node(cursor, i);
		struct index_entry *entry = cursor->path[i].next - 1;
		assert(bnode->entries <= entry);
		assert(entry < bnode->entries + bcount(bnode));
		/*
		 * If this entry is most left, it should be same key
		 * with parent. Otherwise, most left key may not be
		 * correct as next key.
		 */
		if (bnode->entries == entry)
			assert(be64_to_cpu(entry->key) == key);
		else
			assert(be64_to_cpu(entry->key) > key);

		block = be64_to_cpu(entry->block);
		key = be64_to_cpu(entry->key);
	}
}
#else
static inline void cursor_check(struct cursor *cursor) {}
#endif

struct buffer_head *cursor_leafbuf(struct cursor *cursor)
{
	assert(cursor->level == cursor->btree->root.depth - 1);
	return cursor->path[cursor->level].buffer;
}

static void cursor_root_add(struct cursor *cursor, struct buffer_head *buffer,
			    struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(cursor->level < cursor->maxlevel);
	assert(cursor->path[cursor->level + 1].buffer == FREE_BUFFER);
	assert(cursor->path[cursor->level + 1].next == FREE_NEXT);
#endif
	vecmove(cursor->path + 1, cursor->path, cursor->level + 1);
	cursor->level++;
	cursor->path[0].buffer = buffer;
	cursor->path[0].next = next;
}

static void level_replace_blockput(struct cursor *cursor, int level,
				   struct buffer_head *buffer,
				   struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(buffer);
	assert(level <= cursor->level);
	assert(cursor->path[level].buffer != FREE_BUFFER);
	assert(cursor->path[level].next != FREE_NEXT);
#endif
	blockput(cursor->path[level].buffer);
	cursor->path[level].buffer = buffer;
	cursor->path[level].next = next;
}

static void cursor_push(struct cursor *cursor, struct buffer_head *buffer,
			struct index_entry *next)
{
	cursor->level++;
#ifdef CURSOR_DEBUG
	assert(cursor->level <= cursor->maxlevel);
	assert(cursor->path[cursor->level].buffer == FREE_BUFFER);
	assert(cursor->path[cursor->level].next == FREE_NEXT);
#endif
	cursor->path[cursor->level].buffer = buffer;
	cursor->path[cursor->level].next = next;
}

static int cursor_push_one(struct cursor *cursor, struct buffer_head *buffer)
{
	struct btree *btree = cursor->btree;
	struct index_entry *next;
	int ret;

	assert(btree->root.depth >= 1);

	/* Is this the bnode level? */
	if (cursor->level < btree->root.depth - 2) {
		struct bnode *bnode = bufdata(buffer);
		assert(!bnode_sniff(bnode));
		next = bnode->entries;
		ret = 1;
	} else {
		assert(!btree->ops->leaf_sniff(btree, bufdata(buffer)));
		next = NULL;
		ret = 0;
	}
	cursor_push(cursor, buffer, next);
	cursor_check(cursor);

	return ret;
}

static struct buffer_head *cursor_pop(struct cursor *cursor)
{
	struct buffer_head *buffer;

#ifdef CURSOR_DEBUG
	assert(cursor->level >= 0);
#endif
	buffer = cursor->path[cursor->level].buffer;
#ifdef CURSOR_DEBUG
	cursor->path[cursor->level].buffer = FREE_BUFFER;
	cursor->path[cursor->level].next = FREE_NEXT;
#endif
	cursor->level--;
	return buffer;
}

static inline void cursor_pop_blockput(struct cursor *cursor)
{
	blockput(cursor_pop(cursor));
}

/* There is no next entry? */
static inline int level_finished(struct cursor *cursor, int level)
{
	struct bnode *node = level_node(cursor, level);
	return cursor->path[level].next == node->entries + bcount(node);
}
// also write level_beginning!!!

void release_cursor(struct cursor *cursor)
{
	while (cursor->level >= 0)
		cursor_pop_blockput(cursor);
}

/* unused */
void show_cursor(struct cursor *cursor, int depth)
{
	__tux3_dbg(">>> cursor %p/%i:", cursor, depth);
	for (int i = 0; i < depth; i++) {
		__tux3_dbg(" [%Lx/%i]",
			   bufindex(cursor->path[i].buffer),
			   bufcount(cursor->path[i].buffer));
	}
	__tux3_dbg("\n");
}

static inline int alloc_cursor_size(int count)
{
	return sizeof(struct cursor) + sizeof(struct path_level) * count;
}

struct cursor *alloc_cursor(struct btree *btree, int extra)
{
	int extra_depth = btree->root.depth + extra;
	struct cursor *cursor;

	cursor = kmalloc(alloc_cursor_size(extra_depth), GFP_NOFS);
	if (cursor) {
		cursor->btree = btree;
		cursor->level = -1;
#ifdef CURSOR_DEBUG
		cursor->maxlevel = extra_depth - 1;
		for (int i = 0; i < extra_depth; i++) {
			cursor->path[i].buffer = FREE_BUFFER; /* for debug */
			cursor->path[i].next = FREE_NEXT; /* for debug */
		}
#endif
	}
	return cursor;
}

void free_cursor(struct cursor *cursor)
{
#ifdef CURSOR_DEBUG
	if (cursor)
		assert(cursor->level == -1);
#endif
	kfree(cursor);
}

/* Lookup the index entry contains key */
static struct index_entry *bnode_lookup(struct bnode *node, tuxkey_t key)
{
	struct index_entry *next = node->entries, *top = next + bcount(node);
	assert(bcount(node) > 0);
	/* binary search goes here */
	while (++next < top) {
		if (be64_to_cpu(next->key) > key)
			break;
	}
	return next - 1;
}

static int cursor_level_finished(struct cursor *cursor)
{
	/* must not be leaf */
	assert(cursor->level < cursor->btree->root.depth - 1);
	return level_finished(cursor, cursor->level);
}

/*
 * Climb up the cursor until we find the first level where we have not yet read
 * all the way to the end of the index block, there we find the key that
 * separates the subtree we are in (a leaf) from the next subtree to the right.
 */
tuxkey_t cursor_next_key(struct cursor *cursor)
{
	int level = cursor->level;
	assert(level == cursor->btree->root.depth - 1);
	while (level--) {
		if (!level_finished(cursor, level))
			return be64_to_cpu(cursor->path[level].next->key);
	}
	return TUXKEY_LIMIT;
}

static tuxkey_t cursor_level_next_key(struct cursor *cursor)
{
	int level = cursor->level;
	assert(level < cursor->btree->root.depth - 1);
	while (level >= 0) {
		if (!level_finished(cursor, level))
			return be64_to_cpu(cursor->path[level].next->key);
		level--;
	}
	return TUXKEY_LIMIT;
}

/* Return key of this leaf */
tuxkey_t cursor_this_key(struct cursor *cursor)
{
	assert(cursor->level == cursor->btree->root.depth - 1);
	if (cursor->btree->root.depth == 1)
		return 0;
	return be64_to_cpu((cursor->path[cursor->level - 1].next - 1)->key);
}

static tuxkey_t cursor_level_this_key(struct cursor *cursor)
{
	assert(cursor->level < cursor->btree->root.depth - 1);
	if (cursor->level < 0)
		return 0;
	return be64_to_cpu((cursor->path[cursor->level].next - 1)->key);
}

/*
 * Cursor read root node/leaf.
 * < 0 - error
 *   0 - there is no further child (leaf was pushed)
 *   1 - there is child
 */
static int cursor_read_root(struct cursor *cursor)
{
	struct btree *btree = cursor->btree;
	struct buffer_head *buffer;

	assert(has_root(btree));

	buffer = vol_bread(btree->sb, btree->root.block);
	if (!buffer)
		return -EIO; /* FIXME: stupid, it might have been NOMEM */

	return cursor_push_one(cursor, buffer);
}

/*
 * Cursor up to parent node.
 * 0 - there is no further parent (root was popped)
 * 1 - there is parent
 */
static int cursor_advance_up(struct cursor *cursor)
{
	assert(cursor->level >= 0);
	cursor_pop_blockput(cursor);
	return cursor->level >= 0;
}

/*
 * Cursor down to child node or leaf, and update ->next.
 * < 0 - error
 *   0 - there is no further child (leaf was pushed)
 *   1 - there is child
 */
static int cursor_advance_down(struct cursor *cursor)
{
	struct btree *btree = cursor->btree;
	struct buffer_head *buffer;
	block_t child;

	assert(cursor->level < btree->root.depth - 1);

	child = be64_to_cpu(cursor->path[cursor->level].next->block);
	buffer = vol_bread(btree->sb, child);
	if (!buffer)
		return -EIO; /* FIXME: stupid, it might have been NOMEM */
	cursor->path[cursor->level].next++;

	return cursor_push_one(cursor, buffer);
}

/*
 * Cursor advance for btree traverse.
 * < 0 - error
 *   0 - Finished traverse
 *   1 - Reached leaf
 */
static int cursor_advance(struct cursor *cursor)
{
	int ret;

	do {
		if (!cursor_advance_up(cursor))
			return 0;
	} while (cursor_level_finished(cursor));
	do {
		ret = cursor_advance_down(cursor);
		if (ret < 0)
			return ret;
	} while (ret);

	return 1;
}

/* Lookup index and set it as next down path */
static void cursor_bnode_lookup(struct cursor *cursor, tuxkey_t key)
{
	struct path_level *at = &cursor->path[cursor->level];
	at->next = bnode_lookup(bufdata(at->buffer), key);
}

int btree_probe(struct cursor *cursor, tuxkey_t key)
{
	int ret;

	ret = cursor_read_root(cursor);
	if (ret < 0)
		return ret;

	while (ret) {
		cursor_bnode_lookup(cursor, key);

		ret = cursor_advance_down(cursor);
		if (ret < 0)
			goto error;
	}

	return 0;

error:
	release_cursor(cursor);
	return ret;
}

/*
 * Traverse btree for specified range
 * key: start to traverse (cursor should point leaf is including key)
 * len: length to traverse
 *
 * return value:
 * < 0 - error
 *   0 - traversed all range
 * 0 < - traverse was stopped by func, and return value of func
 */
int btree_traverse(struct cursor *cursor, tuxkey_t key, u64 len,
		   btree_traverse_func_t func, void *data)
{
	struct btree *btree = cursor->btree;
	int ret;

	do {
		tuxkey_t bottom = cursor_this_key(cursor);
		tuxkey_t limit = cursor_next_key(cursor);
		void *leaf = bufdata(cursor_leafbuf(cursor));
		assert(!btree->ops->leaf_sniff(btree, leaf));

		if (key < bottom) {
			len -= min_t(u64, len, bottom - key);
			if (len == 0)
				break;
			key = bottom;
		}

		ret = func(btree, bottom, limit, leaf, key, len, data);
		/* Stop traverse if ret >= 1, or error */
		if (ret)
			goto out;

		/* If next key is out of range, done */
		if (key + len <= limit)
			break;

		ret = cursor_advance(cursor);
		if (ret < 0)
			goto out;
	} while (ret);

	ret = 0;
out:
	return ret;
}

static void level_redirect_blockput(struct cursor *cursor, int level, struct buffer_head *clone)
{
	struct buffer_head *buffer = cursor->path[level].buffer;
	struct index_entry *next = cursor->path[level].next;

	/* If this level has ->next, update ->next to the clone buffer */
	if (next)
		next = ptr_redirect(next, bufdata(buffer), bufdata(clone));

	memcpy(bufdata(clone), bufdata(buffer), bufsize(clone));
	level_replace_blockput(cursor, level, clone, next);
}

static int leaf_need_redirect(struct sb *sb, struct buffer_head *buffer)
{
	/* FIXME: leaf doesn't have delta number, we might want to
	 * remove exception for leaf */
	/* If this is not re-dirty, we need to redirect */
	return !buffer_dirty(buffer);
}

static int bnode_need_redirect(struct sb *sb, struct buffer_head *buffer)
{
	/* If this is not re-dirty for sb->unify, we need to redirect */
	return !buffer_already_dirty(buffer, sb->unify);
}

/*
 * Recursively redirect non-dirty buffers on path to modify leaf.
 *
 * Redirect order is from root to leaf. Otherwise, blocks of path will
 * be allocated by reverse order.
 *
 * FIXME: We can allocate/copy blocks before change common ancestor
 * (before changing common ancestor, changes are not visible for
 * reader). With this, we may be able to reduce locking time.
 */
int cursor_redirect(struct cursor *cursor)
{
	struct btree *btree = cursor->btree;
	struct sb *sb = btree->sb;
	int level;

	for (level = 0; level < btree->root.depth; level++) {
		struct buffer_head *buffer, *clone;
		block_t parent, oldblock, newblock;
		struct index_entry *entry;
		int redirect, is_leaf = (level == btree->root.depth - 1);

		buffer = cursor->path[level].buffer;
		/* If buffer needs to redirect to dirty, redirect it */
		if (is_leaf)
			redirect = leaf_need_redirect(sb, buffer);
		else
			redirect = bnode_need_redirect(sb, buffer);

		/* No need to redirect */
		if (!redirect)
			continue;

		/* Redirect buffer before changing */
		clone = new_block(btree);
		if (IS_ERR(clone))
			return PTR_ERR(clone);
		oldblock = bufindex(buffer);
		newblock = bufindex(clone);
		trace("redirect %Lx to %Lx", oldblock, newblock);
		level_redirect_blockput(cursor, level, clone);
		if (is_leaf) {
			/* This is leaf buffer */
			mark_buffer_dirty_atomic(clone);
			log_leaf_redirect(sb, oldblock, newblock);
			defer_bfree(sb, &sb->defree, oldblock, 1);
		} else {
			/* This is bnode buffer */
			mark_buffer_unify_atomic(clone);
			log_bnode_redirect(sb, oldblock, newblock);
			defer_bfree(sb, &sb->deunify, oldblock, 1);
		}

		trace("update parent");
		if (!level) {
			/* Update pointer in btree->root */
			trace("redirect root");
			assert(oldblock == btree->root.block);
			btree->root.block = newblock;
			tux3_mark_btree_dirty(btree);
			continue;
		}
		/* Update entry on parent for the redirected block */
		parent = bufindex(cursor->path[level - 1].buffer);
		entry = cursor->path[level - 1].next - 1;
		entry->block = cpu_to_be64(newblock);
		log_bnode_update(sb, parent, newblock, be64_to_cpu(entry->key));
	}

	cursor_check(cursor);
	return 0;
}

/* Deletion */

static void bnode_remove_index(struct bnode *node, struct index_entry *p,
			       int count)
{
	unsigned total = bcount(node);
	void *end = node->entries + total;
	memmove(p, p + count, end - (void *)(p + count));
	node->count = cpu_to_be32(total - count);
}

static int bnode_merge_nodes(struct sb *sb, struct bnode *into,
			     struct bnode *from)
{
	unsigned into_count = bcount(into), from_count = bcount(from);

	if (from_count + into_count > sb->entries_per_node)
		return 0;

	veccopy(&into->entries[into_count], from->entries, from_count);
	into->count = cpu_to_be32(into_count + from_count);

	return 1;
}

static void adjust_parent_sep(struct cursor *cursor, int level, __be64 newsep)
{
	/* Update separating key until nearest common parent */
	while (level >= 0) {
		struct path_level *parent_at = &cursor->path[level];
		struct index_entry *parent = parent_at->next - 1;

		assert(0 < be64_to_cpu(parent->key));
		assert(be64_to_cpu(parent->key) < be64_to_cpu(newsep));
		log_bnode_adjust(cursor->btree->sb,
				 bufindex(parent_at->buffer),
				 be64_to_cpu(parent->key),
				 be64_to_cpu(newsep));
		parent->key = newsep;
		mark_buffer_unify_non(parent_at->buffer);

		if (parent != level_node(cursor, level)->entries)
			break;

		level--;
	}
}

/* Tracking info for chopped bnode indexes */
struct chopped_index_info {
	tuxkey_t start;
	int count;
};

static void remove_index(struct cursor *cursor, struct chopped_index_info *cii)
{
	int level = cursor->level;
	struct bnode *node = level_node(cursor, level);
	struct chopped_index_info *ciil = &cii[level];

	/* Collect chopped index in this node for logging later */
	if (!ciil->count)
		ciil->start = be64_to_cpu((cursor->path[level].next - 1)->key);
	ciil->count++;

	/* Remove an index */
	bnode_remove_index(node, cursor->path[level].next - 1, 1);
	--(cursor->path[level].next);
	mark_buffer_unify_non(cursor->path[level].buffer);

	/*
	 * Climb up to common parent and update separating key.
	 *
	 * What if index is now empty?  (no deleted key)
	 *
	 * Then some key above is going to be deleted and used to set sep
	 * Climb the cursor while at first entry, bail out at root find the
	 * node with the old sep, set it to deleted key
	 */

	/* There is no separator for last entry or root node */
	if (!level || cursor_level_finished(cursor))
		return;
	/* If removed index was not first entry, no change to separator */
	if (cursor->path[level].next != node->entries)
		return;

	adjust_parent_sep(cursor, level - 1, cursor->path[level].next->key);
}

static int try_leaf_merge(struct btree *btree, struct buffer_head *intobuf,
			  struct buffer_head *frombuf)
{
	struct vleaf *from = bufdata(frombuf);
	struct vleaf *into = bufdata(intobuf);

	/* Try to merge leaves */
	if (btree->ops->leaf_merge(btree, into, from)) {
		struct sb *sb = btree->sb;
		/*
		 * We know frombuf is redirected and dirty. So, in
		 * here, we can just cancel leaf_redirect by bfree(),
		 * instead of defered_bfree()
		 * FIXME: we can optimize freeing leaf without
		 * leaf_redirect, and if we did, this is not true.
		 */
		bfree(sb, bufindex(frombuf), 1);
		log_leaf_free(sb, bufindex(frombuf));
		return 1;
	}
	return 0;
}

static int try_bnode_merge(struct sb *sb, struct buffer_head *intobuf,
			   struct buffer_head *frombuf)
{
	struct bnode *into = bufdata(intobuf);
	struct bnode *from = bufdata(frombuf);

	/* Try to merge nodes */
	if (bnode_merge_nodes(sb, into, from)) {
		/*
		 * We know frombuf is redirected and dirty. So, in
		 * here, we can just cancel bnode_redirect by bfree(),
		 * instead of defered_bfree()
		 * FIXME: we can optimize freeing bnode without
		 * bnode_redirect, and if we did, this is not true.
		 */
		bfree(sb, bufindex(frombuf), 1);
		log_bnode_merge(sb, bufindex(frombuf), bufindex(intobuf));
		return 1;
	}
	return 0;
}

/*
 * This is range deletion. So, instead of adjusting balance of the
 * space on sibling nodes for each change, this just removes the range
 * and merges from right to left even if it is not same parent.
 *
 *              +--------------- (A, B, C)--------------------+
 *              |                    |                        |
 *     +-- (AA, AB, AC) -+       +- (BA, BB, BC) -+      + (CA, CB, CC) +
 *     |        |        |       |        |       |      |       |      |
 * (AAA,AAB)(ABA,ABB)(ACA,ACB) (BAA,BAB)(BBA)(BCA,BCB)  (CAA)(CBA,CBB)(CCA)
 *
 * [less : A, AA, AAA, AAB, AB, ABA, ABB, AC, ACA, ACB, B, BA ... : greater]
 *
 * If we merged from cousin (or re-distributed), we may have to update
 * the index until common parent. (e.g. removed (ACB), then merged
 * from (BAA,BAB) to (ACA), we have to adjust B in root node to BB)
 *
 * See, adjust_parent_sep().
 *
 * FIXME: no re-distribute. so, we don't guarantee above than 50%
 * space efficiency. And if range is end of key (truncate() case), we
 * don't need to merge, and adjust_parent_sep().
 *
 * FIXME2: we may want to split chop work for each step. instead of
 * blocking for a long time.
 */
int btree_chop(struct btree *btree, tuxkey_t start, u64 len)
{
	struct sb *sb = btree->sb;
	struct btree_ops *ops = btree->ops;
	struct buffer_head **prev;
	struct chopped_index_info *cii;
	struct cursor *cursor;
	tuxkey_t limit;
	int ret, done = 0;

	if (!has_root(btree))
		return 0;

	/* Chop all range if len >= TUXKEY_LIMIT */
	limit = (len >= TUXKEY_LIMIT) ? TUXKEY_LIMIT : start + len;

	prev = kzalloc(sizeof(*prev) * btree->root.depth, GFP_NOFS);
	if (prev == NULL)
		return -ENOMEM;

	cii = kzalloc(sizeof(*cii) * btree->root.depth, GFP_NOFS);
	if (cii == NULL) {
		ret = -ENOMEM;
		goto error_cii;
	}

	cursor = alloc_cursor(btree, 0);
	if (!cursor) {
		ret = -ENOMEM;
		goto error_alloc_cursor;
	}

	down_write(&btree->lock);
	ret = btree_probe(cursor, start);
	if (ret)
		goto error_btree_probe;

	/* Walk leaves */
	while (1) {
		struct buffer_head *leafbuf;
		tuxkey_t this_key;
		int level = cursor->level;

		/*
		 * FIXME: If leaf was merged and freed later, we don't
		 * need to redirect leaf and leaf_chop()
		 */
		ret = cursor_redirect(cursor);
		if (ret)
			goto out;
		leafbuf = cursor_pop(cursor);

		/* Adjust start and len for this leaf */
		this_key = cursor_level_this_key(cursor);
		if (start < this_key) {
			if (limit < TUXKEY_LIMIT)
				len -= this_key - start;
			start = this_key;
		}

		ret = ops->leaf_chop(btree, start, len, bufdata(leafbuf));
		if (ret) {
			if (ret < 0) {
				blockput(leafbuf);
				goto out;
			}
			mark_buffer_dirty_non(leafbuf);
		}

		/* Try to merge this leaf with prev */
		if (prev[level]) {
			if (try_leaf_merge(btree, prev[level], leafbuf)) {
				trace(">>> can merge leaf %p into leaf %p", leafbuf, prev[level]);
				remove_index(cursor, cii);
				mark_buffer_dirty_non(prev[level]);
				blockput_free(sb, leafbuf);
				goto keep_prev_leaf;
			}
			blockput(prev[level]);
		}
		prev[level] = leafbuf;

keep_prev_leaf:

		if (cursor_level_next_key(cursor) >= limit)
			done = 1;
		/* Pop and try to merge finished nodes */
		while (done || cursor_level_finished(cursor)) {
			struct buffer_head *buf;
			struct chopped_index_info *ciil;

			level = cursor->level;
			if (level < 0)
				goto chop_root;
			ciil = &cii[level];

			/* Get merge src buffer, and go parent level */
			buf = cursor_pop(cursor);

			/*
			 * Logging chopped indexes
			 * FIXME: If node is freed later (e.g. merged),
			 * we dont't need to log this
			 */
			if (ciil->count) {
				log_bnode_del(sb, bufindex(buf), ciil->start,
					      ciil->count);
			}
			memset(ciil, 0, sizeof(*ciil));

			/* Try to merge node with prev */
			if (prev[level]) {
				assert(level);
				if (try_bnode_merge(sb, prev[level], buf)) {
					trace(">>> can merge node %p into node %p", buf, prev[level]);
					remove_index(cursor, cii);
					mark_buffer_unify_non(prev[level]);
					blockput_free_unify(sb, buf);
					goto keep_prev_node;
				}
				blockput(prev[level]);
			}
			prev[level] = buf;
keep_prev_node:

			if (!level)
				goto chop_root;
		}

		/* Push back down to leaf level */
		do {
			ret = cursor_advance_down(cursor);
			if (ret < 0)
				goto out;
		} while (ret);
	}

chop_root:
	/* Remove depth if possible */
	while (btree->root.depth > 1 && bcount(bufdata(prev[0])) == 1) {
		trace("drop btree level");
		btree->root.block = bufindex(prev[1]);
		btree->root.depth--;
		tux3_mark_btree_dirty(btree);

		/*
		 * We know prev[0] is redirected and dirty. So, in
		 * here, we can just cancel bnode_redirect by bfree(),
		 * instead of defered_bfree()
		 * FIXME: we can optimize freeing bnode without
		 * bnode_redirect, and if we did, this is not true.
		 */
		bfree(sb, bufindex(prev[0]), 1);
		log_bnode_free(sb, bufindex(prev[0]));
		blockput_free_unify(sb, prev[0]);

		vecmove(prev, prev + 1, btree->root.depth);
	}
	ret = 0;

out:
	for (int i = 0; i < btree->root.depth; i++) {
		if (prev[i])
			blockput(prev[i]);
	}
	release_cursor(cursor);
error_btree_probe:
	up_write(&btree->lock);

	free_cursor(cursor);
error_alloc_cursor:
	kfree(cii);
error_cii:
	kfree(prev);

	return ret;
}

/* root must be initialized by zero */
static void bnode_init_root(struct bnode *root, unsigned count, block_t left,
			    block_t right, tuxkey_t rkey)
{
	root->count		= cpu_to_be32(count);
	root->entries[0].block	= cpu_to_be64(left);
	root->entries[1].block	= cpu_to_be64(right);
	root->entries[1].key	= cpu_to_be64(rkey);
}

/* Insertion */

static void bnode_add_index(struct bnode *node, struct index_entry *p,
			    block_t child, u64 childkey)
{
	unsigned count = bcount(node);
	vecmove(p + 1, p, node->entries + count - p);
	p->block	= cpu_to_be64(child);
	p->key		= cpu_to_be64(childkey);
	node->count	= cpu_to_be32(count + 1);
}

static void bnode_split(struct bnode *src, unsigned pos, struct bnode *dst)
{
	dst->count = cpu_to_be32(bcount(src) - pos);
	src->count = cpu_to_be32(pos);

	memcpy(&dst->entries[0], &src->entries[pos],
	       bcount(dst) * sizeof(struct index_entry));
}

/*
 * Insert new leaf to next cursor position.
 * keep == 1: keep current cursor position.
 * keep == 0, set cursor position to new leaf.
 */
static int insert_leaf(struct cursor *cursor, tuxkey_t childkey, struct buffer_head *leafbuf, int keep)
{
	struct btree *btree = cursor->btree;
	struct sb *sb = btree->sb;
	int level = btree->root.depth - 1;
	block_t childblock = bufindex(leafbuf);

	if (keep)
		blockput(leafbuf);
	else {
		cursor_pop_blockput(cursor);
		cursor_push(cursor, leafbuf, NULL);
	}
	while (level--) {
		struct path_level *at = &cursor->path[level];
		struct buffer_head *parentbuf = at->buffer;
		struct bnode *parent = bufdata(parentbuf);

		/* insert and exit if not full */
		if (bcount(parent) < btree->sb->entries_per_node) {
			bnode_add_index(parent, at->next, childblock, childkey);
			if (!keep)
				at->next++;
			log_bnode_add(sb, bufindex(parentbuf), childblock, childkey);
			mark_buffer_unify_non(parentbuf);
			cursor_check(cursor);
			return 0;
		}

		/* split a full index node */
		struct buffer_head *newbuf = new_node(btree);
		if (IS_ERR(newbuf))
			return PTR_ERR(newbuf);

		struct bnode *newnode = bufdata(newbuf);
		unsigned half = bcount(parent) / 2;
		u64 newkey = be64_to_cpu(parent->entries[half].key);

		bnode_split(parent, half, newnode);
		log_bnode_split(sb, bufindex(parentbuf), half, bufindex(newbuf));

		/* if the cursor is in the new node, use that as the parent */
		int child_is_left = at->next <= parent->entries + half;
		if (!child_is_left) {
			struct index_entry *newnext;
			mark_buffer_unify_non(parentbuf);
			newnext = newnode->entries + (at->next - &parent->entries[half]);
			get_bh(newbuf);
			level_replace_blockput(cursor, level, newbuf, newnext);
			parentbuf = newbuf;
			parent = newnode;
		} else
			mark_buffer_unify_non(newbuf);

		bnode_add_index(parent, at->next, childblock, childkey);
		if (!keep)
			at->next++;
		log_bnode_add(sb, bufindex(parentbuf), childblock, childkey);
		mark_buffer_unify_non(parentbuf);

		childkey = newkey;
		childblock = bufindex(newbuf);
		blockput(newbuf);

		/*
		 * If child is in left bnode, we should keep the
		 * cursor position to child, otherwise adjust cursor
		 * to new bnode.
		 */
		keep = child_is_left;
	}

	/* Make new root bnode */
	trace("add tree level");
	struct buffer_head *newbuf = new_node(btree);
	if (IS_ERR(newbuf))
		return PTR_ERR(newbuf);

	struct bnode *newroot = bufdata(newbuf);
	block_t newrootblock = bufindex(newbuf);
	block_t oldrootblock = btree->root.block;
	int left_node = bufindex(cursor->path[0].buffer) != childblock;
	bnode_init_root(newroot, 2, oldrootblock, childblock, childkey);
	cursor_root_add(cursor, newbuf, newroot->entries + 1 + !left_node);
	log_bnode_root(sb, newrootblock, 2, oldrootblock, childblock, childkey);

	/* Change btree to point the new root */
	btree->root.block = newrootblock;
	btree->root.depth++;

	mark_buffer_unify_non(newbuf);
	tux3_mark_btree_dirty(btree);
	cursor_check(cursor);

	return 0;
}

/* Insert new leaf to next cursor position, then set cursor to new leaf */
int btree_insert_leaf(struct cursor *cursor, tuxkey_t key, struct buffer_head *leafbuf)
{
	return insert_leaf(cursor, key, leafbuf, 0);
}

/*
 * Split leaf, then insert to parent.
 * key:  key to add after split (cursor will point leaf which is including key)
 * hint: hint for split
 *
 * return value:
 *   0 - success
 * < 0 - error
 */
static int btree_leaf_split(struct cursor *cursor, tuxkey_t key, tuxkey_t hint)
{
	trace("split leaf");
	struct btree *btree = cursor->btree;
	struct buffer_head *newbuf;

	newbuf = new_leaf(btree);
	if (IS_ERR(newbuf))
		return PTR_ERR(newbuf);
	log_balloc(btree->sb, bufindex(newbuf), 1);

	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	tuxkey_t newkey = btree->ops->leaf_split(btree, hint, bufdata(leafbuf),
						 bufdata(newbuf));
	assert(cursor_this_key(cursor) < newkey);
	assert(newkey < cursor_next_key(cursor));
	if (key < newkey)
		mark_buffer_dirty_non(newbuf);
	else
		mark_buffer_dirty_non(leafbuf);
	return insert_leaf(cursor, newkey, newbuf, key < newkey);
}

static int btree_advance(struct cursor *cursor, struct btree_key_range *key)
{
	tuxkey_t limit = cursor_next_key(cursor);
	int skip = 0;

	while (key->start >= limit) {
		int ret = cursor_advance(cursor);
		assert(ret != 0);	/* wrong key range? */
		if (ret < 0)
			return ret;

		limit = cursor_next_key(cursor);
		skip++;
	}
	if (skip > 1) {
		/* key should on next leaf */
		tux3_dbg("skipped more than 1 leaf: why, and probe is better");
		assert(0);
	}

	return 0;
}

int noop_pre_write(struct btree *btree, tuxkey_t key_bottom, tuxkey_t key_limit,
		   void *leaf, struct btree_key_range *key)
{
	return BTREE_DO_DIRTY;
}

int btree_write(struct cursor *cursor, struct btree_key_range *key)
{
	struct btree *btree = cursor->btree;
	struct btree_ops *ops = btree->ops;
	tuxkey_t split_hint;
	int err;

	while (key->len > 0) {
		tuxkey_t bottom, limit;
		void *leaf;
		int ret;

		err = btree_advance(cursor, key);
		if (err)
			return err;	/* FIXME: error handling */

		bottom = cursor_this_key(cursor);
		limit = cursor_next_key(cursor);
		assert(bottom <= key->start && key->start < limit);

		leaf = bufdata(cursor_leafbuf(cursor));
		ret = ops->leaf_pre_write(btree, bottom, limit, leaf, key);
		assert(ret >= 0);
		if (ret == BTREE_DO_RETRY)
			continue;

		if (ret == BTREE_DO_DIRTY) {
			err = cursor_redirect(cursor);
			if (err)
				return err;	/* FIXME: error handling */

			/* Reread leaf after redirect */
			leaf = bufdata(cursor_leafbuf(cursor));
			assert(!ops->leaf_sniff(btree, leaf));

			ret = ops->leaf_write(btree, bottom, limit, leaf, key,
					      &split_hint);
			if (ret < 0)
				return ret;
			if (ret == BTREE_DO_RETRY) {
				mark_buffer_dirty_non(cursor_leafbuf(cursor));
				continue;
			}
		}

		if (ret == BTREE_DO_SPLIT) {
			err = btree_leaf_split(cursor, key->start, split_hint);
			if (err)
				return err;	/* FIXME: error handling */
		}
	}

	return 0;
}

int btree_read(struct cursor *cursor, struct btree_key_range *key)
{
	struct btree *btree = cursor->btree;
	struct btree_ops *ops = btree->ops;
	void *leaf = bufdata(cursor_leafbuf(cursor));
	tuxkey_t bottom = cursor_this_key(cursor);
	tuxkey_t limit = cursor_next_key(cursor);

	/* FIXME: we might be better to support multiple leaves */

	assert(bottom <= key->start && key->start < limit);
	assert(!ops->leaf_sniff(btree, leaf));

	return ops->leaf_read(btree, bottom, limit, leaf, key);
}

void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops)
{
	btree->sb = sb;
	btree->ops = ops;
	btree->root = root;
	init_rwsem(&btree->lock);
	ops->btree_init(btree);
}

int btree_alloc_empty(struct btree *btree)
{
	struct sb *sb = btree->sb;
	struct buffer_head *leafbuf;
	block_t leafblock;

	assert(!has_root(btree));

	leafbuf = new_leaf(btree);
	if (IS_ERR(leafbuf))
		return PTR_ERR(leafbuf);

	leafblock = bufindex(leafbuf);
	trace("leaf at %Lx", leafblock);
	log_balloc(sb, leafblock, 1);

	mark_buffer_dirty_non(leafbuf);
	blockput(leafbuf);

	btree->root = (struct root){ .block = leafblock, .depth = 1 };
	tux3_mark_btree_dirty(btree);

	return 0;
}

/* FIXME: right? and this should be done by btree_chop()? */
int btree_free_empty(struct btree *btree)
{
	struct sb *sb = btree->sb;
	struct btree_ops *ops = btree->ops;
	struct buffer_head *leafbuf;
	block_t leaf;

	if (!has_root(btree))
		return 0;

	assert(btree->root.depth == 1);
	leaf = btree->root.block;
	/* Make btree has no root */
	btree->root = no_root;
	tux3_mark_btree_dirty(btree);

	leafbuf = vol_find_get_block(sb, leaf);
	if (leafbuf && !leaf_need_redirect(sb, leafbuf)) {
		/*
		 * This is redirected leaf. So, in here, we can just
		 * cancel leaf_redirect by bfree(), instead of
		 * defered_bfree().
		 */
		bfree(sb, leaf, 1);
		log_leaf_free(sb, leaf);
		assert(ops->leaf_can_free(btree, bufdata(leafbuf)));
		blockput_free(sb, leafbuf);
	} else {
		defer_bfree(sb, &sb->defree, leaf, 1);
		log_bfree(sb, leaf, 1);
		if (leafbuf) {
			assert(ops->leaf_can_free(btree, bufdata(leafbuf)));
			blockput(leafbuf);
		}
	}

	return 0;
}

int replay_bnode_redirect(struct replay *rp, block_t oldblock, block_t newblock)
{
	struct sb *sb = rp->sb;
	struct buffer_head *newbuf, *oldbuf;
	int err = 0;

	newbuf = vol_getblk(sb, newblock);
	if (!newbuf) {
		err = -ENOMEM;	/* FIXME: error code */
		goto error;
	}
	oldbuf = vol_bread(sb, oldblock);
	if (!oldbuf) {
		err = -EIO;	/* FIXME: error code */
		goto error_put_newbuf;
	}
	assert(!bnode_sniff(bufdata(oldbuf)));

	memcpy(bufdata(newbuf), bufdata(oldbuf), bufsize(newbuf));
	mark_buffer_unify_atomic(newbuf);

	blockput(oldbuf);
error_put_newbuf:
	blockput(newbuf);
error:
	return err;
}

int replay_bnode_root(struct replay *rp, block_t root, unsigned count,
		      block_t left, block_t right, tuxkey_t rkey)
{
	struct sb *sb = rp->sb;
	struct buffer_head *rootbuf;

	rootbuf = vol_getblk(sb, root);
	if (!rootbuf)
		return -ENOMEM;
	bnode_buffer_init(rootbuf);

	bnode_init_root(bufdata(rootbuf), count, left, right, rkey);

	mark_buffer_unify_atomic(rootbuf);
	blockput(rootbuf);

	return 0;
}

/*
 * Before this replay, replay should already dirty the buffer of src.
 * (e.g. by redirect)
 */
int replay_bnode_split(struct replay *rp, block_t src, unsigned pos,
		       block_t dst)
{
	struct sb *sb = rp->sb;
	struct buffer_head *srcbuf, *dstbuf;
	int err = 0;

	srcbuf = vol_getblk(sb, src);
	if (!srcbuf) {
		err = -ENOMEM;	/* FIXME: error code */
		goto error;
	}

	dstbuf = vol_getblk(sb, dst);
	if (!dstbuf) {
		err = -ENOMEM;	/* FIXME: error code */
		goto error_put_srcbuf;
	}
	bnode_buffer_init(dstbuf);

	bnode_split(bufdata(srcbuf), pos, bufdata(dstbuf));

	mark_buffer_unify_non(srcbuf);
	mark_buffer_unify_atomic(dstbuf);

	blockput(dstbuf);
error_put_srcbuf:
	blockput(srcbuf);
error:
	return err;
}

/*
 * Before this replay, replay should already dirty the buffer of bnodeblock.
 * (e.g. by redirect)
 */
static int replay_bnode_change(struct sb *sb, block_t bnodeblock,
			       u64 val1, u64 val2,
			       void (*change)(struct bnode *, u64, u64))
{
	struct buffer_head *bnodebuf;

	bnodebuf = vol_getblk(sb, bnodeblock);
	if (!bnodebuf)
		return -ENOMEM;	/* FIXME: error code */

	struct bnode *bnode = bufdata(bnodebuf);
	change(bnode, val1, val2);

	mark_buffer_unify_non(bnodebuf);
	blockput(bnodebuf);

	return 0;
}

static void add_func(struct bnode *bnode, u64 child, u64 key)
{
	struct index_entry *entry = bnode_lookup(bnode, key) + 1;
	bnode_add_index(bnode, entry, child, key);
}

int replay_bnode_add(struct replay *rp, block_t parent, block_t child,
		     tuxkey_t key)
{
	return replay_bnode_change(rp->sb, parent, child, key, add_func);
}

static void update_func(struct bnode *bnode, u64 child, u64 key)
{
	struct index_entry *entry = bnode_lookup(bnode, key);
	assert(be64_to_cpu(entry->key) == key);
	entry->block = cpu_to_be64(child);
}

int replay_bnode_update(struct replay *rp, block_t parent, block_t child,
			tuxkey_t key)
{
	return replay_bnode_change(rp->sb, parent, child, key, update_func);
}

int replay_bnode_merge(struct replay *rp, block_t src, block_t dst)
{
	struct sb *sb = rp->sb;
	struct buffer_head *srcbuf, *dstbuf;
	int err = 0, ret;

	srcbuf = vol_getblk(sb, src);
	if (!srcbuf) {
		err = -ENOMEM;	/* FIXME: error code */
		goto error;
	}

	dstbuf = vol_getblk(sb, dst);
	if (!dstbuf) {
		err = -ENOMEM;	/* FIXME: error code */
		goto error_put_srcbuf;
	}

	ret = bnode_merge_nodes(sb, bufdata(dstbuf), bufdata(srcbuf));
	assert(ret == 1);

	mark_buffer_unify_non(dstbuf);
	mark_buffer_unify_non(srcbuf);

	blockput(dstbuf);
error_put_srcbuf:
	blockput_free_unify(sb, srcbuf);
error:
	return err;
}

static void del_func(struct bnode *bnode, u64 key, u64 count)
{
	struct index_entry *entry = bnode_lookup(bnode, key);
	assert(be64_to_cpu(entry->key) == key);
	bnode_remove_index(bnode, entry, count);
}

int replay_bnode_del(struct replay *rp, block_t bnode, tuxkey_t key,
		     unsigned count)
{
	return replay_bnode_change(rp->sb, bnode, key, count, del_func);
}

static void adjust_func(struct bnode *bnode, u64 from, u64 to)
{
	struct index_entry *entry = bnode_lookup(bnode, from);
	assert(be64_to_cpu(entry->key) == from);
	entry->key = cpu_to_be64(to);
}

int replay_bnode_adjust(struct replay *rp, block_t bnode, tuxkey_t from,
			tuxkey_t to)
{
	return replay_bnode_change(rp->sb, bnode, from, to, adjust_func);
}
