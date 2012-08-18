/*
 * Generic btree operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 2
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
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

struct bnode
{
	be_u32 count, unused;
	struct index_entry { be_u64 key; be_u64 block; } __packed entries[];
} __packed;

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
	return from_be_u32(node->count);
}

static struct buffer_head *new_block(struct btree *btree)
{
	block_t block;

	int err = btree->ops->balloc(btree->sb, 1, &block);
	if (err)
		return ERR_PTR(err);
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

static struct buffer_head *new_node(struct btree *btree)
{
	struct buffer_head *buffer = new_block(btree);

	if (!IS_ERR(buffer)) {
		memset(bufdata(buffer), 0, bufsize(buffer));
		mark_buffer_rollup_atomic(buffer);
	}
	return buffer;
}

/*
 * A btree cursor has n + 1 entries for a btree of depth n, with the first n
 * entries pointing at internal nodes and entry n + 1 pointing at a leaf.
 * The next field points at the next index entry that will be loaded in a left
 * to right tree traversal, not the current entry.  The next pointer is null
 * for the leaf, which has its own specialized traversal algorithms.
 */

static inline struct bnode *level_node(struct cursor *cursor, int level)
{
	return bufdata(cursor->path[level].buffer);
}

struct buffer_head *cursor_leafbuf(struct cursor *cursor)
{
	assert(cursor->level == cursor->btree->root.depth);
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

static void level_replace_blockput(struct cursor *cursor, int level, struct buffer_head *buffer, struct index_entry *next)
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

void cursor_push(struct cursor *cursor, struct buffer_head *buffer, struct index_entry *next)
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
	printf(">>> cursor %p/%i:", cursor, depth);
	for (int i = 0; i < depth; i++)
		printf(" [%Lx/%i]", (L)bufindex(cursor->path[i].buffer), bufcount(cursor->path[i].buffer));
	printf("\n");
}

static void cursor_check(struct cursor *cursor)
{
	if (cursor->level == -1)
		return;
	tuxkey_t key = 0;
	block_t block = cursor->btree->root.block;

	for (int i = 0; i <= cursor->level; i++) {
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
			assert(from_be_u64(entry->key) == key);
		else
			assert(from_be_u64(entry->key) > key);

		block = from_be_u64(entry->block);
		key = from_be_u64(entry->key);
	}
}

static inline int alloc_cursor_size(int count)
{
	return sizeof(struct cursor) + sizeof(struct path_level) * count;
}

struct cursor *alloc_cursor(struct btree *btree, int extra)
{
	int maxlevel = btree->root.depth + extra;
	struct cursor *cursor = malloc(alloc_cursor_size(maxlevel + 1));

	if (cursor) {
		cursor->btree = btree;
		cursor->level = -1;
#ifdef CURSOR_DEBUG
		cursor->maxlevel = maxlevel;
		for (int i = 0; i <= maxlevel; i++) {
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
	assert(cursor->level == -1);
#endif
	free(cursor);
}

/* Lookup the index entry contains key */
static struct index_entry *bnode_lookup(struct bnode *node, tuxkey_t key)
{
	struct index_entry *next = node->entries, *top = next + bcount(node);
	assert(bcount(node) > 0);
	/* binary search goes here */
	while (++next < top) {
		if (from_be_u64(next->key) > key)
			break;
	}
	return next - 1;
}

static int cursor_level_finished(struct cursor *cursor)
{
	/* must not be leaf */
	assert(cursor->level < cursor->btree->root.depth);
	return level_finished(cursor, cursor->level);
}

/*
 * Cursor read root node.
 * < 0 - error
 *   0 - success
 */
static int cursor_read_root(struct cursor *cursor)
{
	struct btree *btree = cursor->btree;
	struct buffer_head *buffer;

	assert(has_root(btree));

	buffer = vol_bread(btree->sb, btree->root.block);
	if (!buffer)
		return -EIO; /* FIXME: stupid, it might have been NOMEM */
	cursor_push(cursor, buffer, ((struct bnode *)bufdata(buffer))->entries);
	return 0;
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

	assert(cursor->level < btree->root.depth);

	child = from_be_u64(cursor->path[cursor->level].next->block);
	buffer = vol_bread(btree->sb, child);
	if (!buffer)
		return -EIO; /* FIXME: stupid, it might have been NOMEM */
	cursor->path[cursor->level].next++;

	if (cursor->level < btree->root.depth - 1) {
		struct bnode *node = bufdata(buffer);
		cursor_push(cursor, buffer, node->entries);
		cursor_check(cursor);
		return 1;
	}

	assert(btree->ops->leaf_sniff(btree, bufdata(buffer)));
	cursor_push(cursor, buffer, NULL);
	cursor_check(cursor);
	return 0;
}

/*
 * Cursor advance for btree traverse.
 * < 0 - error
 *   0 - Finished traverse
 *   1 - Reached leaf
 */
int cursor_advance(struct cursor *cursor)
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
	do {
		cursor_bnode_lookup(cursor, key);

		ret = cursor_advance_down(cursor);
		if (ret < 0)
			goto error;
	} while (ret);

	return 0;

error:
	release_cursor(cursor);
	return ret;
}

/*
 * Climb up the cursor until we find the first level where we have not yet read
 * all the way to the end of the index block, there we find the key that
 * separates the subtree we are in (a leaf) from the next subtree to the right.
 */
static be_u64 *next_keyp(struct cursor *cursor, int depth)
{
	for (int level = depth; level--;)
		if (!level_finished(cursor, level))
			return &cursor->path[level].next->key;
	return NULL;
}

tuxkey_t next_key(struct cursor *cursor, int depth)
{
	be_u64 *keyp = next_keyp(cursor, depth);

	return keyp ? from_be_u64(*keyp) : -1;
}
// also write this_key!!!

void show_tree_range(struct btree *btree, tuxkey_t start, unsigned count)
{
	printf("%i level btree at %Li:\n", btree->root.depth, (L)btree->root.block);
	if (!has_root(btree))
		return;

	struct cursor *cursor = alloc_cursor(btree, 0);
	if (!cursor)
		error("out of memory");
	if (btree_probe(cursor, start))
		error("tell me why!!!");
	struct buffer_head *buffer;
	do {
		buffer = cursor_leafbuf(cursor);
		assert((btree->ops->leaf_sniff)(btree, bufdata(buffer)));
		(btree->ops->leaf_dump)(btree, bufdata(buffer));
		//tuxkey_t *next = pnext_key(cursor, btree->depth);
		//printf("next key = %Lx:\n", next ? (L)*next : 0);
	} while (--count && cursor_advance(cursor));
	free_cursor(cursor);
}

void show_tree(struct btree *btree)
{
	show_tree_range(btree, 0, -1);
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

int cursor_redirect(struct cursor *cursor)
{
#ifndef ATOMIC
	return 0;
#endif
	struct btree *btree = cursor->btree;
	unsigned level = btree->root.depth;
	struct sb *sb = btree->sb;
	block_t uninitialized_var(child);

	while (1) {
		struct buffer_head *buffer;
		block_t uninitialized_var(oldblock);
		block_t uninitialized_var(newblock);
		int redirected = 0;

		buffer = cursor->path[level].buffer;
		/* If buffer is not dirty, redirect it to modify */
		if (!buffer_dirty(buffer)) {
			redirected = 1;

			/* Redirect buffer before changing */
			struct buffer_head *clone = new_block(btree);
			if (IS_ERR(clone))
				return PTR_ERR(clone);
			oldblock = bufindex(buffer);
			newblock = bufindex(clone);
			trace("redirect %Lx to %Lx", (L)oldblock, (L)newblock);
			level_redirect_blockput(cursor, level, clone);
			if (level == btree->root.depth) {
				/* This is leaf buffer */
				mark_buffer_dirty_atomic(clone);
				log_leaf_redirect(sb, oldblock, newblock);
				defer_bfree(&sb->defree, oldblock, 1);
				goto parent_level;
			}
			/* This is bnode buffer */
			mark_buffer_rollup_atomic(clone);
			log_bnode_redirect(sb, oldblock, newblock);
			defer_bfree(&sb->derollup, oldblock, 1);
		} else {
			if (level == btree->root.depth) {
				/* This is leaf buffer */
				goto parent_level;
			}
		}

		/* Update entry for the redirected child block */
		trace("update parent");
		block_t block = bufindex(cursor->path[level].buffer);
		struct index_entry *entry = cursor->path[level].next - 1;
		entry->block = to_be_u64(child);
		log_bnode_update(sb, block, child, from_be_u64(entry->key));

parent_level:
		/* If it is already redirected, ancestor is also redirected */
		if (!redirected) {
			cursor_check(cursor);
			return 0;
		}

		if (!level--) {
			trace("redirect root");
			assert(oldblock == btree->root.block);
			btree->root.block = newblock;
			mark_btree_dirty(btree);
			cursor_check(cursor);
			return 0;
		}
		child = newblock;
	}
}

/* Deletion */

static void remove_index(struct cursor *cursor)
{
	int level = cursor->level;
	struct bnode *node = level_node(cursor, level);
	int count = bcount(node), i;

	/* stomps the node count (if 0th key holds count) */
	memmove(cursor->path[level].next - 1, cursor->path[level].next,
		(char *)&node->entries[count] - (char *)cursor->path[level].next);
	node->count = to_be_u32(count - 1);
	--(cursor->path[level].next);
	mark_buffer_rollup_non(cursor->path[level].buffer);

	/* no separator for last entry */
	if (cursor_level_finished(cursor))
		return;
	/*
	 * Climb up to common parent and set separating key to deleted key.
	 * What if index is now empty?  (no deleted key)
	 * Then some key above is going to be deleted and used to set sep
	 * Climb the cursor while at first entry, bail out at root
	 * find the node with the old sep, set it to deleted key
	 */
	if (cursor->path[level].next == node->entries && level) {
		be_u64 sep = (cursor->path[level].next)->key;
		for (i = level - 1; cursor->path[i].next - 1 == level_node(cursor, i)->entries; i--)
			if (!i)
				return;
		(cursor->path[i].next - 1)->key = sep;
		mark_buffer_rollup_non(cursor->path[i].buffer);
	}
}

static void merge_nodes(struct bnode *node, struct bnode *node2)
{
	veccopy(&node->entries[bcount(node)], node2->entries, bcount(node2));
	node->count = to_be_u32(bcount(node) + bcount(node2));
}

static void blockput_free(struct btree *btree, struct buffer_head *buffer)
{
	struct sb *sb = btree->sb;
	block_t block = bufindex(buffer);

	if (bufcount(buffer) != 1) {
		warn("free block %Lx/%x still in use!", (L)bufindex(buffer), bufcount(buffer));
		blockput(buffer);
		assert(bufcount(buffer) == 0);
		return;
	}
	blockput(buffer);
	/* FIXME: ->derollup (and log_bfree_rollup) or ->defree? */
	defer_bfree(&sb->defree, block, 1);
	log_bfree(sb, block, 1);
	set_buffer_empty(buffer); // free it!!! (and need a buffer free state)
}

int btree_chop(struct btree *btree, struct btree_chop_info *info, millisecond_t deadline)
{
	int depth = btree->root.depth, suspend = 0;
	struct cursor *cursor;
	struct buffer_head *leafbuf, **prev, *leafprev = NULL;
	struct btree_ops *ops = btree->ops;
	struct sb *sb = btree->sb;
	int ret;

	if (!has_root(btree))
		return 0;

	cursor = alloc_cursor(btree, 0);
	prev = malloc(sizeof(*prev) * depth);
	memset(prev, 0, sizeof(*prev) * depth);

	down_write(&btree->lock);
	btree_probe(cursor, info->key);	/* FIXME: info->resume? */

	/* Walk leaves */
	while (1) {
		if ((ret = cursor_redirect(cursor)))
			goto out;
		leafbuf = cursor_pop(cursor);

		ret = (ops->leaf_chop)(btree, info->key, bufdata(leafbuf));
		if (ret) {
			if (ret < 0)
				goto error_leaf_chop;
			mark_buffer_dirty_non(leafbuf);
		}

		/* Try to merge this leaf with prev */
		if (leafprev) {
			struct vleaf *this = bufdata(leafbuf);
			struct vleaf *that = bufdata(leafprev);
			/* Try to merge leaf with prev */
			if ((ops->leaf_need)(btree, this) <= (ops->leaf_free)(btree, that)) {
				trace(">>> can merge leaf %p into leaf %p", leafbuf, leafprev);
				(ops->leaf_merge)(btree, that, this);
				remove_index(cursor);
				mark_buffer_dirty_non(leafprev);
				blockput_free(btree, leafbuf);
				//dirty_buffer_count_check(sb);
				goto keep_prev_leaf;
			}
			blockput(leafprev);
		}
		leafprev = leafbuf;
keep_prev_leaf:

		//nanosleep(&(struct timespec){ 0, 50 * 1000000 }, NULL);
		//printf("time remaining: %Lx\n", deadline - gettime());
//		if (deadline && gettime() > deadline)
//			suspend = -1;
		if (info->blocks && info->freed >= info->blocks)
			suspend = -1;

		/* pop and try to merge finished nodes */
		while (suspend || cursor_level_finished(cursor)) {
			struct buffer_head *buf;
			int level = cursor->level;

			/* Get merge src buffer, and go parent level */
			buf = cursor_pop(cursor);
			/* try to merge node with prev */
			if (prev[level]) {
				assert(level);
				struct bnode *this = bufdata(buf);
				struct bnode *that = bufdata(prev[level]);
				trace_off("check node %p against %p", this, that);
				trace_off("this count = %i prev count = %i", bcount(this), bcount(that));
				/* try to merge with node to left */
				if (bcount(this) <= sb->entries_per_node - bcount(that)) {
					trace(">>> can merge node %p into node %p", this, that);
					merge_nodes(that, this);
					remove_index(cursor);
					mark_buffer_rollup_non(prev[level]);
					blockput_free(btree, buf);
					//dirty_buffer_count_check(sb);
					goto keep_prev_node;
				}
				blockput(prev[level]);
			}
			prev[level] = buf;
keep_prev_node:

			/* deepest key in the cursor is the resume address */
			if (suspend == -1 && !cursor_level_finished(cursor)) {
				suspend = 1; /* only set resume once */
				info->resume = from_be_u64((cursor->path[level].next)->key);
			}
			if (!level) { /* remove depth if possible */
				while (depth > 1 && bcount(bufdata(prev[0])) == 1) {
					trace("drop btree level");
					btree->root.block = bufindex(prev[1]);
					blockput_free(btree, prev[0]);
					//dirty_buffer_count_check(sb);
					depth = --btree->root.depth;
					mark_btree_dirty(btree);
					vecmove(prev, prev + 1, depth);
					//set_sb_dirty(sb);
				}
				//sb->snapmask &= ~snapmask; delete_snapshot_from_disk();
				//set_sb_dirty(sb);
				//save_sb(sb);
				ret = suspend;
				goto out;
			}
		}

		/* push back down to leaf level */
		do {
			ret = cursor_advance_down(cursor);
			if (ret < 0)
				goto out;
		} while (ret);
	}

error_leaf_chop:
	blockput(leafbuf);
out:
	if (leafprev)
		blockput(leafprev);
	for (int i = 0; i < btree->root.depth; i++) {
		if (prev[i])
			blockput(prev[i]);
	}
	free(prev);
	release_cursor(cursor);
	up_write(&btree->lock);
	free_cursor(cursor);
	return ret;
}

/* root must be initialized by zero */
static void bnode_init_root(struct bnode *root, unsigned count, block_t left,
			    block_t right, tuxkey_t rkey)
{
	root->count		= to_be_u32(count);
	root->entries[0].block	= to_be_u64(left);
	root->entries[1].block	= to_be_u64(right);
	root->entries[1].key	= to_be_u64(rkey);
}

/* Insertion */

static void bnode_add_index(struct bnode *node, struct index_entry *p,
			    block_t child, u64 childkey)
{
	unsigned count = bcount(node);
	vecmove(p + 1, p, node->entries + count - p);
	p->block	= to_be_u64(child);
	p->key		= to_be_u64(childkey);
	node->count	= to_be_u32(count + 1);
}

static void bnode_split(struct bnode *src, unsigned pos, struct bnode *dst)
{
	dst->count = to_be_u32(bcount(src) - pos);
	src->count = to_be_u32(pos);

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
	int level = btree->root.depth;
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
			mark_buffer_rollup_non(parentbuf);
			return 0;
		}

		/* split a full index node */
		struct buffer_head *newbuf = new_node(btree);
		if (IS_ERR(newbuf))
			return PTR_ERR(newbuf);

		struct bnode *newnode = bufdata(newbuf);
		unsigned half = bcount(parent) / 2;
		u64 newkey = from_be_u64(parent->entries[half].key);

		bnode_split(parent, half, newnode);
		log_bnode_split(sb, bufindex(parentbuf), half, bufindex(newbuf));

		/* if the cursor is in the new node, use that as the parent */
		int child_is_left = at->next <= parent->entries + half;
		if (!child_is_left) {
			struct index_entry *newnext;
			mark_buffer_rollup_non(parentbuf);
			newnext = newnode->entries + (at->next - &parent->entries[half]);
			get_bh(newbuf);
			level_replace_blockput(cursor, level, newbuf, newnext);
			parentbuf = newbuf;
			parent = newnode;
		} else
			mark_buffer_rollup_non(newbuf);

		bnode_add_index(parent, at->next, childblock, childkey);
		if (!keep)
			at->next++;
		log_bnode_add(sb, bufindex(parentbuf), childblock, childkey);
		mark_buffer_rollup_non(parentbuf);

		childkey = newkey;
		childblock = bufindex(newbuf);
		blockput(newbuf);

		/*
		 * if child is in left bnode, we should keep the
		 * cursor position to child, not splited new bnode.
		 */
		if (child_is_left)
			keep = 1;
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

	mark_buffer_rollup_non(newbuf);
	mark_btree_dirty(btree);
	cursor_check(cursor);

	return 0;
}

/* Insert new leaf to next cursor position, then set cursor to new leaf */
int btree_insert_leaf(struct cursor *cursor, tuxkey_t key, struct buffer_head *leafbuf)
{
	return insert_leaf(cursor, key, leafbuf, 0);
}

static int btree_leaf_split(struct cursor *cursor, tuxkey_t key)
{
	trace("split leaf");
	struct btree *btree = cursor->btree;
	struct buffer_head *newbuf;

	newbuf = new_leaf(btree);
	if (IS_ERR(newbuf))
		return PTR_ERR(newbuf);
	log_balloc(btree->sb, bufindex(newbuf), 1);

	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	tuxkey_t newkey = (btree->ops->leaf_split)(btree, key, bufdata(leafbuf), bufdata(newbuf));
	if (key < newkey)
		mark_buffer_dirty_non(newbuf);
	else
		mark_buffer_dirty_non(leafbuf);
	return insert_leaf(cursor, newkey, newbuf, key < newkey);
}

void *btree_expand(struct cursor *cursor, tuxkey_t key, unsigned newsize)
{
	struct btree *btree = cursor->btree;
	int err;

	/* This redirects for the both of changing and spliting the leaf */
	err = cursor_redirect(cursor);
	if (err)
		goto error;

	for (int i = 0; i < 2; i++) {
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		void *space = (btree->ops->leaf_resize)(btree, key, bufdata(leafbuf), newsize);
		if (space)
			return space;
		assert(!i);
		err = btree_leaf_split(cursor, key);
		if (err) {
			warn("insert_node failed (%d)", err);
			break;
		}
	}
error:
	return ERR_PTR(err);
}

void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops)
{
	btree->sb = sb;
	btree->ops = ops;
	btree->root = root;
	init_rwsem(&btree->lock);
	ops->btree_init(btree);
}

int alloc_empty_btree(struct btree *btree)
{
	struct sb *sb = btree->sb;
	struct buffer_head *rootbuf = new_node(btree);
	if (IS_ERR(rootbuf))
		goto error;
	struct buffer_head *leafbuf = new_leaf(btree);
	if (IS_ERR(leafbuf))
		goto error_leafbuf;

	assert(!has_root(btree));
	struct bnode *rootnode = bufdata(rootbuf);
	block_t rootblock = bufindex(rootbuf);
	block_t leafblock = bufindex(leafbuf);
	trace("root at %Lx", (L)rootblock);
	trace("leaf at %Lx", (L)leafblock);
	bnode_init_root(rootnode, 1, leafblock, 0, 0);
	log_bnode_root(sb, rootblock, 1, leafblock, 0, 0);
	log_balloc(sb, leafblock, 1);

	mark_buffer_dirty_non(rootbuf);
	blockput(rootbuf);
	mark_buffer_dirty_non(leafbuf);
	blockput(leafbuf);

	btree->root = (struct root){ .block = rootblock, .depth = 1 };
	mark_btree_dirty(btree);

	return 0;

error_leafbuf:
	(btree->ops->bfree)(sb, bufindex(rootbuf), 1);
	blockput(rootbuf);
	rootbuf = leafbuf;
error:
	return PTR_ERR(rootbuf);
}

/* FIXME: right? and this should be done by btree_chop()? */
int free_empty_btree(struct btree *btree)
{
	if (!has_root(btree))
		return 0;

	assert(btree->root.depth == 1);
	struct sb *sb = btree->sb;
	struct buffer_head *rootbuf = vol_bread(sb, btree->root.block);
	if (!rootbuf)
		return -EIO;
	struct bnode *rootnode = bufdata(rootbuf);
	assert(bcount(rootnode) == 1);
	/* FIXME: ->derollup (and log_bfree_rollup) or ->defree? */
	defer_bfree(&sb->defree, from_be_u64(rootnode->entries[0].block), 1);
	log_bfree(sb, from_be_u64(rootnode->entries[0].block), 1);
	defer_bfree(&sb->defree, bufindex(rootbuf), 1);
	log_bfree(sb, bufindex(rootbuf), 1);
	blockput(rootbuf);
	return 0;
}

int replay_bnode_redirect(struct sb *sb, block_t oldblock, block_t newblock)
{
	struct buffer_head *newbuf, *oldbuf;
	int err = 0;

	newbuf = vol_getblk(sb, newblock);
	if (IS_ERR(newbuf)) {
		err = PTR_ERR(newbuf);
		goto error;
	}
	oldbuf = vol_bread(sb, oldblock);
	if (IS_ERR(oldbuf)) {
		err = PTR_ERR(oldbuf);
		goto error_put_newbuf;
	}

	memcpy(bufdata(newbuf), bufdata(oldbuf), bufsize(newbuf));
	mark_buffer_rollup_atomic(newbuf);

	blockput(oldbuf);
error_put_newbuf:
	blockput(newbuf);
error:
	return err;
}

int replay_bnode_root(struct sb *sb, block_t root, unsigned count,
		      block_t left, block_t right, tuxkey_t rkey)
{
	struct buffer_head *rootbuf;

	rootbuf = vol_getblk(sb, root);
	if (!rootbuf)
		return -ENOMEM;
	memset(bufdata(rootbuf), 0, bufsize(rootbuf));

	bnode_init_root(bufdata(rootbuf), count, left, right, rkey);

	mark_buffer_rollup_atomic(rootbuf);
	blockput(rootbuf);

	return 0;
}

/*
 * Before this replay, replay should already dirty the buffer of src.
 * (e.g. by redirect)
 */
int replay_bnode_split(struct sb *sb, block_t src, unsigned pos, block_t dst)
{
	struct buffer_head *srcbuf, *dstbuf;
	int err = 0;

	srcbuf = vol_getblk(sb, src);
	if (IS_ERR(srcbuf)) {
		err = -ENOMEM;
		goto error;
	}

	dstbuf = vol_getblk(sb, dst);
	if (IS_ERR(dstbuf)) {
		err = -ENOMEM;
		goto error_put_srcbuf;
	}
	memset(bufdata(dstbuf), 0, bufsize(dstbuf));

	bnode_split(bufdata(srcbuf), pos, bufdata(dstbuf));

	mark_buffer_rollup_non(srcbuf);
	mark_buffer_rollup_atomic(dstbuf);

	blockput(dstbuf);
error_put_srcbuf:
	blockput(srcbuf);
error:
	return err;
}

/*
 * Before this replay, replay should already dirty the buffer of parent.
 * (e.g. by redirect)
 */
static int replay_bnode_change(struct sb *sb, block_t parent, block_t child,
			tuxkey_t key,
			void (*change)(struct bnode *, block_t, tuxkey_t))
{
	struct buffer_head *parentbuf;

	parentbuf = vol_getblk(sb, parent);
	if (IS_ERR(parentbuf))
		return PTR_ERR(parentbuf);

	struct bnode *bnode = bufdata(parentbuf);
	change(bnode, child, key);

	mark_buffer_rollup_non(parentbuf);
	blockput(parentbuf);

	return 0;
}

static void add_func(struct bnode *bnode, block_t child, tuxkey_t key)
{
	struct index_entry *entry = bnode_lookup(bnode, key) + 1;
	bnode_add_index(bnode, entry, child, key);
}

int replay_bnode_add(struct sb *sb, block_t parent, block_t child, tuxkey_t key)
{
	return replay_bnode_change(sb, parent, child, key, add_func);
}

static void update_func(struct bnode *bnode, block_t child, tuxkey_t key)
{
	struct index_entry *entry = bnode_lookup(bnode, key);
	assert(from_be_u64(entry->key) == key);
	entry->block = to_be_u64(child);
}

int replay_bnode_update(struct sb *sb, block_t parent, block_t child, tuxkey_t key)
{
	return replay_bnode_change(sb, parent, child, key, update_func);
}
