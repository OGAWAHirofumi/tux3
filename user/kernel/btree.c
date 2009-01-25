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

struct bnode
{
	be_u32 count, unused;
	struct index_entry { be_u64 key; be_u64 block; } PACKED entries[];
} PACKED;
/*
 * Note that the first key of an index block is never accessed.  This is
 * because for a btree, there is always one more key than nodes in each
 * index node.  In other words, keys lie between node pointers.  I
 * micro-optimize by placing the node count in the first key, which allows
 * a node to contain an esthetically pleasing binary number of pointers.
 * (Not done yet.)
 */

static inline unsigned bcount(struct bnode *node)
{
	return from_be_u32(node->count);
}

// desperately need ERR_PTR return here to distinguish between
// ENOMEM, which should be impossible but when it happens we
// need to do something reasonable, or ENOSPC which we must
// just report and keep going without a fuss.
static struct buffer_head *new_block(struct btree *btree)
{
	block_t block;
	int err = btree->ops->balloc(btree->sb, 1, &block);
	if (err)
		return NULL; // ERR_PTR me!!!
	struct buffer_head *buffer = vol_getblk(btree->sb, block);
	if (!buffer)
		return NULL;
	memset(bufdata(buffer), 0, bufsize(buffer));
	mark_buffer_dirty(buffer);
	return buffer;
}

struct buffer_head *new_leaf(struct btree *btree)
{
	struct buffer_head *buffer = new_block(btree);
	if (buffer)
		(btree->ops->leaf_init)(btree, bufdata(buffer));
	return buffer;
}

static struct buffer_head *new_node(struct btree *btree)
{
	struct buffer_head *buffer = new_block(btree);
	if (buffer)
		((struct bnode *)bufdata(buffer))->count = 0;
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

static void level_replace_brelse(struct cursor *cursor, int level, struct buffer_head *buffer, struct index_entry *next)
{
#ifdef CURSOR_DEBUG
	assert(buffer);
	assert(level < cursor->len);
	assert(cursor->path[level].buffer != FREE_BUFFER);
	assert(cursor->path[level].next != FREE_NEXT);
#endif
	brelse(cursor->path[level].buffer);
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

static void level_pop_brelse(struct cursor *cursor)
{
	brelse(level_pop(cursor));
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
		level_pop_brelse(cursor);
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

int probe(struct btree *btree, tuxkey_t key, struct cursor *cursor)
{
	unsigned i, depth = btree->root.depth;
	struct buffer_head *buffer = vol_bread(btree->sb, btree->root.block);
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

int advance(struct btree *btree, struct cursor *cursor)
{
	int depth = btree->root.depth, level = depth;
	struct buffer_head *buffer;
	do {
		level_pop_brelse(cursor);
		if (!level)
			return 0;
		level--;
	} while (level_finished(cursor, level));
	while (1) {
		buffer = vol_bread(btree->sb, from_be_u64(cursor->path[level].next->block));
		if (!buffer)
			goto eek;
		cursor->path[level].next++;
		if (level + 1 == depth)
			break;
		level_push(cursor, buffer, ((struct bnode *)bufdata(buffer))->entries);
		level++;
	}
	level_push(cursor, buffer, NULL);
	cursor_check(cursor);
	return 1;
eek:
	release_cursor(cursor);
	return -EIO;
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
	struct cursor *cursor = alloc_cursor(btree, 0);
	if (!cursor)
		error("out of memory");
	if (probe(btree, start, cursor))
		error("tell me why!!!");
	struct buffer_head *buffer;
	do {
		buffer = cursor_leafbuf(cursor);
		assert((btree->ops->leaf_sniff)(btree, bufdata(buffer)));
		(btree->ops->leaf_dump)(btree, bufdata(buffer));
		//tuxkey_t *next = pnext_key(cursor, btree->depth);
		//printf("next key = %Lx:\n", next ? (L)*next : 0);
	} while (--count && advance(btree, cursor));
	free_cursor(cursor);
}

void show_tree(struct btree *btree)
{
	show_tree_range(btree, 0, -1);
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

static void brelse_free(struct btree *btree, struct buffer_head *buffer)
{
	struct sb *sb = btree->sb;
	block_t block = bufindex(buffer);
	if (bufcount(buffer) != 1) {
		warn("free block %Lx/%x still in use!", (L)bufindex(buffer), bufcount(buffer));
		brelse(buffer);
		assert(bufcount(buffer) == 0);
		return;
	}
	brelse(buffer);
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

	cursor = alloc_cursor(btree, 0);
	prev = malloc(sizeof(*prev) * depth);
	memset(prev, 0, sizeof(*prev) * depth);

	down_write(&btree->lock);
	probe(btree, info->resume, cursor);
	leafbuf = level_pop(cursor);

	/* leaf walk */
	while (1) {
		ret = (ops->leaf_chop)(btree, info->key, bufdata(leafbuf));
		if (ret) {
			mark_buffer_dirty(leafbuf);
			if (ret < 0)
				goto error_leaf_chop;
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
				brelse_free(btree, leafbuf);
				//dirty_buffer_count_check(sb);
				goto keep_prev_leaf;
			}
			brelse(leafprev);
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
					brelse_free(btree, level_pop(cursor));
					//dirty_buffer_count_check(sb);
					goto keep_prev_node;
				}
				brelse(prev[level]);
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
					brelse_free(btree, prev[0]);
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
	brelse(leafbuf);
out:
	if (leafprev)
		brelse(leafprev);
	for (int i = 0; i < btree->root.depth; i++) {
		if (prev[i])
			brelse(prev[i]);
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
	int depth = btree->root.depth;
	block_t childblock = bufindex(leafbuf);
	if (keep)
		brelse(leafbuf);
	else {
		level_pop_brelse(cursor);
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
			mark_buffer_dirty(parentbuf);
			return 0;
		}

		/* split a full index node */
		struct buffer_head *newbuf = new_node(btree);
		if (!newbuf)
			goto eek;
		struct bnode *newnode = bufdata(newbuf);
		unsigned half = bcount(parent) / 2;
		u64 newkey = from_be_u64(parent->entries[half].key);
		newnode->count = to_be_u32(bcount(parent) - half);
		memcpy(&newnode->entries[0], &parent->entries[half], bcount(newnode) * sizeof(struct index_entry));
		parent->count = to_be_u32(half);

		/* if the cursor is in the new node, use that as the parent */
		if (at->next > parent->entries + half) {
			struct index_entry *newnext;
			mark_buffer_dirty(parentbuf);
			newnext = newnode->entries + (at->next - &parent->entries[half]);
			get_bh(newbuf);
			level_replace_brelse(cursor, depth, newbuf, newnext);
			parentbuf = newbuf;
			parent = newnode;
		}
		add_child(parent, at->next, childblock, childkey);
		if (!keep)
			at->next++;
		mark_buffer_dirty(parentbuf);
		childkey = newkey;
		childblock = bufindex(newbuf);
		brelse(newbuf);
	}
	trace("add tree level");
	struct buffer_head *newbuf = new_node(btree);
	if (!newbuf)
		goto eek;
	struct bnode *newroot = bufdata(newbuf);
	int left_node = bufindex(cursor->path[0].buffer) != childblock;
	newroot->count = to_be_u32(2);
	newroot->entries[0].block = to_be_u64(btree->root.block);
	newroot->entries[1].key = to_be_u64(childkey);
	newroot->entries[1].block = to_be_u64(childblock);
	btree->root.block = bufindex(newbuf);
	btree->root.depth++;
	level_root_add(cursor, newbuf, newroot->entries + 1 + !left_node);
	mark_btree_dirty(btree);
	cursor_check(cursor);
	return 0;
eek:
	release_cursor(cursor);
	return -ENOMEM;
}

/* Insert new leaf to next cursor position, then set cursor to new leaf */
int btree_insert_leaf(struct cursor *cursor, tuxkey_t key, struct buffer_head *leafbuf)
{
	return insert_leaf(cursor, key, leafbuf, 0);
}

int btree_leaf_split(struct btree *btree, struct cursor *cursor, tuxkey_t key)
{
	trace("split leaf");
	struct buffer_head *newbuf = new_leaf(btree);
	if (!newbuf) {
		/* the rule: release cursor at point of error */
		release_cursor(cursor);
		return -ENOMEM;
	}
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);
	tuxkey_t newkey = (btree->ops->leaf_split)(btree, key, bufdata(leafbuf), bufdata(newbuf));
	mark_buffer_dirty(leafbuf);
	return insert_leaf(cursor, newkey, newbuf, key < newkey);
}

void *tree_expand(struct btree *btree, tuxkey_t key, unsigned newsize, struct cursor *cursor)
{
	for (int i = 0; i < 2; i++) {
		struct buffer_head *leafbuf = cursor_leafbuf(cursor);
		void *space = (btree->ops->leaf_resize)(btree, key, bufdata(leafbuf), newsize);
		if (space)
			return space;
		assert(!i);
		int err = btree_leaf_split(btree, cursor, key);
		if (err) {
			warn("insert_node failed (%d)", err);
			break;
		}
	}
	return NULL;
}

void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops)
{
	btree->sb = sb;
	btree->ops = ops;
	btree->root = root;
	init_rwsem(&btree->lock);
	ops->btree_init(btree);
}

int new_btree(struct btree *btree, struct sb *sb, struct btree_ops *ops)
{
	/* Initialize btree with dummy root */
	init_btree(btree, sb, (struct root){}, ops);

	struct buffer_head *rootbuf = new_node(btree);
	struct buffer_head *leafbuf = new_leaf(btree);
	if (!rootbuf || !leafbuf)
		goto eek;
	trace("root at %Lx\n", (L)bufindex(rootbuf));
	trace("leaf at %Lx\n", (L)bufindex(leafbuf));
	struct bnode *rootnode = bufdata(rootbuf);
	rootnode->entries[0].block = to_be_u64(bufindex(leafbuf));
	rootnode->count = to_be_u32(1);
	btree->root = (struct root){ .block = bufindex(rootbuf), .depth = 1 };
	brelse(rootbuf);
	brelse(leafbuf);
	return 0;
eek:
	if (rootbuf)
		brelse(rootbuf);
	if (leafbuf)
		brelse(leafbuf);
	return -ENOMEM;
}

/* userland only */
void free_btree(struct btree *btree)
{
	// write me
}
