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

static inline struct bnode *cursor_node(struct cursor *cursor, int level)
{
	return bufdata(cursor->path[level].buffer);
}

struct buffer_head *cursor_leafbuf(struct cursor *cursor)
{
	assert(cursor->len >= 2); /* root-bnode + leaf >= 2 */
	return cursor->path[cursor->len - 1].buffer;
}

static void level_root_add(struct cursor *cursor, struct buffer_head *buffer,
			   struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(cursor->len < cursor->maxlen);
	assert(cursor->path[cursor->len].buffer == FREE_BUFFER);
	assert(cursor->path[cursor->len].next == FREE_NEXT);
#endif
	vecmove(cursor->path + 1, cursor->path, cursor->len);
	cursor->len++;
	cursor->path[0].buffer = buffer;
	cursor->path[0].next = next;
}

static void level_replace_blockput(struct cursor *cursor, int level, struct buffer_head *buffer, struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(buffer);
	assert(level < cursor->len);
	assert(cursor->path[level].buffer != FREE_BUFFER);
	assert(cursor->path[level].next != FREE_NEXT);
#endif
	blockput(cursor->path[level].buffer);
	cursor->path[level].buffer = buffer;
	cursor->path[level].next = next;
}

void level_push(struct cursor *cursor, struct buffer_head *buffer, struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(cursor->len < cursor->maxlen);
	assert(cursor->path[cursor->len].buffer == FREE_BUFFER);
	assert(cursor->path[cursor->len].next == FREE_NEXT);
#endif
	cursor->path[cursor->len].buffer = buffer;
	cursor->path[cursor->len].next = next;
	cursor->len++;
}

static struct buffer_head *level_pop(struct cursor *cursor)
{
	struct buffer_head *buffer;

#ifdef CURSOR_DEBUG
	assert(cursor->len > 0);
#endif
	cursor->len--;
	buffer = cursor->path[cursor->len].buffer;
#ifdef CURSOR_DEBUG
	cursor->path[cursor->len].buffer = FREE_BUFFER;
	cursor->path[cursor->len].next = FREE_NEXT;
#endif
	return buffer;
}

static void level_pop_blockput(struct cursor *cursor)
{
	blockput(level_pop(cursor));
}

static inline int level_finished(struct cursor *cursor, int level)
{
	struct bnode *node = cursor_node(cursor, level);

	return cursor->path[level].next == node->entries + bcount(node);
}
// also write level_beginning!!!

void release_cursor(struct cursor *cursor)
{
	while (cursor->len)
		level_pop_blockput(cursor);
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
	if (cursor->len == 0)
		return;
	tuxkey_t key = 0;
	block_t block = cursor->btree->root.block;

	for (int i = 0; i < cursor->len; i++) {
		assert(bufindex(cursor->path[i].buffer) == block);
		if (!cursor->path[i].next)
			break;
		struct bnode *node = cursor_node(cursor, i);
		assert(node->entries < cursor->path[i].next);
		assert(cursor->path[i].next <= node->entries + bcount(node));
		assert(from_be_u64((cursor->path[i].next - 1)->key) >= key);
		block = from_be_u64((cursor->path[i].next - 1)->block);
		key = from_be_u64((cursor->path[i].next - 1)->key);
	}
}

static inline int alloc_cursor_size(int maxlevel)
{
	return sizeof(struct cursor) + sizeof(struct path_level) * maxlevel;
}

struct cursor *alloc_cursor(struct btree *btree, int extra)
{
	int maxlevel = btree->root.depth + 1 + extra;
	struct cursor *cursor = malloc(alloc_cursor_size(maxlevel));

	if (cursor) {
		cursor->btree = btree;
		cursor->len = 0;
#ifdef CURSOR_DEBUG
		cursor->maxlen = maxlevel;
		for (int i = 0; i < maxlevel; i++) {
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
	assert(cursor->len == 0);
#endif
	free(cursor);
}

int probe(struct cursor *cursor, tuxkey_t key)
{
	struct btree *btree = cursor->btree;
	unsigned i, depth = btree->root.depth;
	struct buffer_head *buffer;

	assert(has_root(btree));
	buffer = vol_bread(btree->sb, btree->root.block);
	if (!buffer)
		return -EIO;
	struct bnode *node = bufdata(buffer);

	for (i = 0; i < depth; i++) {
		struct index_entry *next = node->entries, *top = next + bcount(node);
		while (++next < top) /* binary search goes here */
			if (from_be_u64(next->key) > key)
				break;
		trace("probe level %i, %ti of %i", i, next - node->entries, bcount(node));
		level_push(cursor, buffer, next);
		if (!(buffer = vol_bread(btree->sb, from_be_u64((next - 1)->block))))
			goto eek;
		node = (struct bnode *)bufdata(buffer);
	}
	assert((btree->ops->leaf_sniff)(btree, bufdata(buffer)));
	level_push(cursor, buffer, NULL);
	cursor_check(cursor);
	return 0;
eek:
	release_cursor(cursor);
	return -EIO; /* stupid, it might have been NOMEM */
}

int advance(struct cursor *cursor)
{
	struct btree *btree = cursor->btree;
	int depth = btree->root.depth, level = depth;
	struct buffer_head *buffer;

	do {
		level_pop_blockput(cursor);
		if (!level)
			return 0;
		level--;
	} while (level_finished(cursor, level));
	while (1) {
		buffer = vol_bread(btree->sb, from_be_u64(cursor->path[level].next->block));
		if (!buffer)
			return -EIO;
		cursor->path[level].next++;
		if (level + 1 == depth)
			break;
		level_push(cursor, buffer, ((struct bnode *)bufdata(buffer))->entries);
		level++;
	}
	level_push(cursor, buffer, NULL);
	cursor_check(cursor);
	return 1;
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
	if (probe(cursor, start))
		error("tell me why!!!");
	struct buffer_head *buffer;
	do {
		buffer = cursor_leafbuf(cursor);
		assert((btree->ops->leaf_sniff)(btree, bufdata(buffer)));
		(btree->ops->leaf_dump)(btree, bufdata(buffer));
		//tuxkey_t *next = pnext_key(cursor, btree->depth);
		//printf("next key = %Lx:\n", next ? (L)*next : 0);
	} while (--count && advance(cursor));
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
		next = bufdata(clone) + ((void *)next - bufdata(buffer));

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

static void remove_index(struct cursor *cursor, int level)
{
	struct bnode *node = cursor_node(cursor, level);
	int count = bcount(node), i;

	/* stomps the node count (if 0th key holds count) */
	memmove(cursor->path[level].next - 1, cursor->path[level].next,
		(char *)&node->entries[count] - (char *)cursor->path[level].next);
	node->count = to_be_u32(count - 1);
	--(cursor->path[level].next);
	mark_buffer_dirty(cursor->path[level].buffer);

	/* no separator for last entry */
	if (level_finished(cursor, level))
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
		for (i = level - 1; cursor->path[i].next - 1 == cursor_node(cursor, i)->entries; i--)
			if (!i)
				return;
		(cursor->path[i].next - 1)->key = sep;
		mark_buffer_dirty(cursor->path[i].buffer);
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
	(btree->ops->bfree)(sb, block, 1);
	set_buffer_empty(buffer); // free it!!! (and need a buffer free state)
}

int tree_chop(struct btree *btree, struct delete_info *info, millisecond_t deadline)
{
	int depth = btree->root.depth, level = depth - 1, suspend = 0;
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
	probe(cursor, info->key);	/* FIXME: info->resume? */
	leafbuf = level_pop(cursor);

	/* leaf walk */
	while (1) {
		if ((ret = cursor_redirect(cursor)))
			goto error_leaf_chop;
		ret = (ops->leaf_chop)(btree, info->key, bufdata(leafbuf));
		if (ret) {
			if (ret < 0)
				goto error_leaf_chop;
			mark_buffer_dirty(leafbuf);
		}

		/* try to merge this leaf with prev */
		if (leafprev) {
			struct vleaf *this = bufdata(leafbuf);
			struct vleaf *that = bufdata(leafprev);
			/* try to merge leaf with prev */
			if ((ops->leaf_need)(btree, this) <= (ops->leaf_free)(btree, that)) {
				trace(">>> can merge leaf %p into leaf %p", leafbuf, leafprev);
				(ops->leaf_merge)(btree, that, this);
				remove_index(cursor, level);
				mark_buffer_dirty(leafprev);
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
		while (suspend || level_finished(cursor, level)) {
			/* try to merge node with prev */
			if (prev[level]) {
				assert(level); /* node has no prev */
				struct bnode *this = cursor_node(cursor, level);
				struct bnode *that = bufdata(prev[level]);
				trace_off("check node %p against %p", this, that);
				trace_off("this count = %i prev count = %i", bcount(this), bcount(that));
				/* try to merge with node to left */
				if (bcount(this) <= sb->entries_per_node - bcount(that)) {
					trace(">>> can merge node %p into node %p", this, that);
					merge_nodes(that, this);
					remove_index(cursor, level - 1);
					mark_buffer_dirty(prev[level]);
					blockput_free(btree, level_pop(cursor));
					//dirty_buffer_count_check(sb);
					goto keep_prev_node;
				}
				blockput(prev[level]);
			}
			prev[level] = level_pop(cursor);
keep_prev_node:

			/* deepest key in the cursor is the resume address */
			if (suspend == -1 && !level_finished(cursor, level)) {
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
			level--;
			trace_off(printf("pop to level %i, block %Lx, %i of %i nodes\n", level, bufindex(cursor->path[level].buffer), cursor->path[level].next - cursor_node(cursor, level)->entries, bcount(cursor_node(cursor, level))););
		}

		/* push back down to leaf level */
		while (level < depth - 1) {
			struct buffer_head *buffer = vol_bread(sb, from_be_u64(cursor->path[level++].next++->block));
			if (!buffer) {
				ret = -EIO;
				goto out;
			}
			level_push(cursor, buffer, ((struct bnode *)bufdata(buffer))->entries);
			trace_off(printf("push to level %i, block %Lx, %i nodes\n", level, bufindex(buffer), bcount(cursor_node(cursor, level))););
		}
		//dirty_buffer_count_check(sb);
		/* go to next leaf */
		if (!(leafbuf = vol_bread(sb, from_be_u64(cursor->path[level].next++->block)))) {
			ret = -EIO;
			goto out;
		}
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

/* Insertion */

static void add_child(struct bnode *node, struct index_entry *p, block_t child, u64 childkey)
{
	vecmove(p + 1, p, node->entries + bcount(node) - p);
	p->block = to_be_u64(child);
	p->key = to_be_u64(childkey);
	node->count = to_be_u32(bcount(node) + 1);
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
	int depth = btree->root.depth;
	block_t childblock = bufindex(leafbuf);

	if (keep)
		blockput(leafbuf);
	else {
		level_pop_blockput(cursor);
		level_push(cursor, leafbuf, NULL);
	}
	while (depth--) {
		struct path_level *at = cursor->path + depth;
		struct buffer_head *parentbuf = at->buffer;
		struct bnode *parent = bufdata(parentbuf);

		/* insert and exit if not full */
		if (bcount(parent) < btree->sb->entries_per_node) {
			add_child(parent, at->next, childblock, childkey);
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
		newnode->count = to_be_u32(bcount(parent) - half);
		memcpy(&newnode->entries[0], &parent->entries[half], bcount(newnode) * sizeof(struct index_entry));
		parent->count = to_be_u32(half);
		log_bnode_split(sb, bufindex(parentbuf), half, bufindex(newbuf));

		/* if the cursor is in the new node, use that as the parent */
		int child_is_left = at->next <= parent->entries + half;
		if (!child_is_left) {
			struct index_entry *newnext;
			mark_buffer_rollup_non(parentbuf);
			newnext = newnode->entries + (at->next - &parent->entries[half]);
			get_bh(newbuf);
			level_replace_blockput(cursor, depth, newbuf, newnext);
			parentbuf = newbuf;
			parent = newnode;
		} else
			mark_buffer_rollup_non(newbuf);

		add_child(parent, at->next, childblock, childkey);
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
	newroot->count = to_be_u32(2);
	newroot->entries[0].block = to_be_u64(oldrootblock);
	newroot->entries[1].key = to_be_u64(childkey);
	newroot->entries[1].block = to_be_u64(childblock);
	level_root_add(cursor, newbuf, newroot->entries + 1 + !left_node);
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

void *tree_expand(struct cursor *cursor, tuxkey_t key, unsigned newsize)
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
	rootnode->entries[0].block = to_be_u64(leafblock);
	rootnode->count = to_be_u32(1);
	btree->root = (struct root){ .block = rootblock, .depth = 1 };

	log_bnode_root(sb, rootblock, 1, leafblock, 0, 0);
	log_balloc(sb, leafblock, 1);

	mark_buffer_dirty_non(rootbuf);
	blockput(rootbuf);
	mark_buffer_dirty_non(leafbuf);
	blockput(leafbuf);

	mark_btree_dirty(btree);

	return 0;

error_leafbuf:
	(btree->ops->bfree)(sb, bufindex(rootbuf), 1);
	blockput(rootbuf);
	rootbuf = leafbuf;
error:
	return PTR_ERR(rootbuf);
}

/* FIXME: right? and this should be done by tree_chop()? */
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
	/* FIXME: error check */
	(btree->ops->bfree)(sb, from_be_u64(rootnode->entries[0].block), 1);
	(btree->ops->bfree)(sb, bufindex(rootbuf), 1);
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
	struct bnode *newroot;

	rootbuf = vol_getblk(sb, root);
	if (!rootbuf)
		return -ENOMEM;
	memset(bufdata(rootbuf), 0, bufsize(rootbuf));

	newroot = bufdata(rootbuf);
	newroot->count = to_be_u32(count);
	newroot->entries[0].block = to_be_u64(left);
	newroot->entries[1].block = to_be_u64(right);
	newroot->entries[1].key = to_be_u64(rkey);

	mark_buffer_rollup_atomic(rootbuf);
	blockput(rootbuf);

	return 0;
}

/*
 * Before this replay, replay should already dirty the buffer of parent.
 * (e.g. by redirect)
 */
int replay_bnode_update(struct sb *sb, block_t parent, block_t child, tuxkey_t key)
{
	struct buffer_head *parentbuf;

	parentbuf = vol_getblk(sb, parent);
	if (IS_ERR(parentbuf))
		return PTR_ERR(parentbuf);

	struct bnode *bnode = bufdata(parentbuf);
	struct index_entry *entry = bnode->entries, *top = entry + bcount(bnode);
	while (entry < top) { /* binary search goes here */
		if (from_be_u64(entry->key) == key)
			break;
		entry++;
	}
	assert(entry < top);

	entry->block = to_be_u64(child);
	mark_buffer_rollup_non(parentbuf);
	blockput(parentbuf);

	return 0;
}
