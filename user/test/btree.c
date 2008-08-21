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
#include "buffer.h"
#include "tux3.h"

#ifndef trace
#define trace trace_off
#endif

typedef struct dleaf leaf_t; // these need to be generic

static millisecond_t gettime(void)
{
	struct timeval now;
	if (gettimeofday(&now, NULL) != -1)
		return now.tv_sec * 1000LL + now.tv_usec / 1000;
	error("gettimeofday failed, %s (%i)", strerror(errno), errno);
	return 0;
}

struct bnode
{
	u32 count, unused;
	struct index_entry { u64 key; block_t block; } entries[];
}; 
/*
 * Note that the first key of an index block is never accessed.  This is
 * because for a btree, there is always one more key than nodes in each
 * index node.  In other words, keys lie between node pointers.  I
 * micro-optimize by placing the node count in the first key, which allows
 * a node to contain an esthetically pleasing binary number of pointers.
 * (Not done yet.)
 */

static void free_block(SB, sector_t block)
{
}

static struct buffer *new_leaf(struct btree *btree)
{
	struct buffer *buffer = getblk(btree->sb->devmap, (btree->ops->balloc)(btree->sb));
	if (!buffer)
		return NULL;
	memset(buffer->data, 0, bufsize(buffer));
	(btree->ops->leaf_init)(btree, buffer->data);
	set_buffer_dirty(buffer);
	return buffer;
}

static struct buffer *new_node(struct btree *btree)
{
	struct buffer *buffer = getblk(btree->sb->devmap, (btree->ops->balloc)(btree->sb));
	if (!buffer)
		return buffer;
	memset(buffer->data, 0, bufsize(buffer));
	struct bnode *node = buffer->data;
	node->count = 0;
	set_buffer_dirty(buffer);
	return buffer;
}

struct path { struct buffer *buffer; struct index_entry *next; };
/*
 * A btree path has n + 1 entries for a btree of depth n, with the first n
 * entries pointing at internal nodes and entry n + 1 pointing at a leaf.
 * The next field points at the next index entry that will be loaded in a left
 * to right tree traversal, not the current entry.  The next pointer is null
 * for the leaf, which has its own specialized traversal algorithms.
 */

static inline struct bnode *path_node(struct path path[], int level)
{
	return (struct bnode *)path[level].buffer->data;
}

static void release_path(struct path *path, int levels)
{
	for (int i = 0; i < levels; i++)
		brelse(path[i].buffer);
}

static int probe(BTREE, tuxkey_t key, struct path *path)
{
	unsigned i, levels = btree->root.levels;
	struct buffer *buffer = bread(btree->sb->devmap, btree->root.block);
	if (!buffer)
		return -EIO;
	struct bnode *node = buffer->data;

	for (i = 0; i < levels; i++) {
		struct index_entry *next = node->entries, *top = next + node->count;
		while (++next < top) /* binary search goes here */
			if (next->key > key)
				break;
		//printf("probe level %i, %ti of %i\n", i, next - node->entries, node->count);
		path[i] = (struct path){ buffer, next };
		if (!(buffer = bread(btree->sb->devmap, (next - 1)->block)))
			goto eek;
		node = (struct bnode *)buffer->data;
	}
	assert((btree->ops->leaf_sniff)(btree, buffer->data));
	path[levels] = (struct path){ buffer };
	return 0;
eek:
	release_path(path, i - 1);
	return -EIO; /* stupid, it might have been NOMEM */
}

static inline int finished_level(struct path path[], int level)
{
	struct bnode *node = path_node(path, level);
	return path[level].next == node->entries + node->count;
}

int advance(struct map *map, struct path *path, int levels)
{
	int level = levels;
	struct buffer *buffer = path[level].buffer;
	struct bnode *node;
	do {
		brelse(buffer);
		if (!level)
			return 0;
		node = (buffer = path[--level].buffer)->data;
		//printf("pop to level %i, %tx of %x\n", level, path[level].next - node->entries, node->count);
	} while (finished_level(path, level));
	do {
		//printf("push from level %i, %tx of %x\n", level, path[level].next - node->entries, node->count);
		if (!(buffer = bread(map, path[level].next++->block)))
			goto eek;
		path[++level] = (struct path){ .buffer = buffer, .next = (node = buffer->data)->entries };
	} while (level < levels);
	return 1;
eek:
	release_path(path, level);
	return -EIO;
}

/*
 * Climb up the path until we find the first level where we have not yet read
 * all the way to the end of the index block, there we find the key that
 * separates the subtree we are in (a leaf) from the next subtree to the right.
 */
tuxkey_t *next_key(struct path *path, int levels)
{
	for (int level = levels; level--;)
		if (!finished_level(path, level))
			return &path[level].next->key;
	return NULL;
}

void show_tree_range(BTREE, tuxkey_t start, unsigned count)
{
	printf("%i level btree %p at %Li:\n", btree->root.levels, btree, (L)btree->root.block);
	struct path path[30]; // check for overflow!!!
	if (probe(btree, start, path))
		error("probe failed for some unknown reason"); // probe should return error!!!
	struct buffer *buffer;
	do {
		buffer = path[btree->root.levels].buffer;
		assert((btree->ops->leaf_sniff)(btree, buffer->data));
		(btree->ops->leaf_dump)(btree, buffer->data);
		//tuxkey_t *next = next_key(path, btree->levels);
		//printf("next key = %Lx:\n", next ? (L)*next : 0);
	} while (--count && advance(buffer->map, path, btree->root.levels));
}

/* Deletion */

static void brelse_free(SB, struct buffer *buffer)
{
	brelse(buffer);
	if (buffer->count) {
		warn("free block %Lx still in use!", (long long)buffer->index);
		return;
	}
	free_block(sb, buffer->index);
	set_buffer_empty(buffer); // free it!!! (and need a buffer free state)
}

static void remove_index(struct path path[], int level)
{
	struct bnode *node = path_node(path, level);
	int count = node->count, i;

	/* stomps the node count (if 0th key holds count) */
	memmove(path[level].next - 1, path[level].next,
		(char *)&node->entries[count] - (char *)path[level].next);
	node->count = count - 1;
	--(path[level].next);
	set_buffer_dirty(path[level].buffer);

	/* no separator for last entry */
	if (finished_level(path, level))
		return;
	/*
	 * Climb up to common parent and set separating key to deleted key.
	 * What if index is now empty?  (no deleted key)
	 * Then some key above is going to be deleted and used to set sep
	 * Climb the path while at first entry, bail out at root
	 * find the node with the old sep, set it to deleted key
	 */
	if (path[level].next == node->entries && level) {
		block_t sep = (path[level].next)->key;
		for (i = level - 1; path[i].next - 1 == path_node(path, i)->entries; i--)
			if (!i)
				return;
		(path[i].next - 1)->key = sep;
		set_buffer_dirty(path[i].buffer);
	}
}

static void merge_nodes(struct bnode *node, struct bnode *node2)
{
	memcpy(&node->entries[node->count], &node2->entries[0], node2->count * sizeof(struct index_entry));
	node->count += node2->count;
}

typedef u32 tag_t;

struct delete_info { tag_t victim, newtag; block_t blocks; block_t resume; int create; };

int delete_from_leaf(SB, leaf_t *leaf, struct delete_info *info, int *freed)
{
	return 0; // write me!!!
}

int delete_tree_partial(BTREE, struct delete_info *info, millisecond_t deadline, int maxblocks)
{
	int levels = btree->root.levels, level = levels - 1, suspend = 0, freed = 0;
	struct path path[levels + 1], prev[levels + 1];
	struct buffer *leafbuf, *leafprev = NULL;
	struct btree_ops *ops = btree->ops;
	struct sb *sb = btree->sb;
	memset(path, 0, sizeof(path));

	probe(btree, info->resume, path);
	leafbuf = path[levels].buffer;

	/* leaf walk */
	while (1) {
		if (delete_from_leaf(sb, leafbuf->data, info, &freed))
			set_buffer_dirty(leafbuf);

		/* try to merge this leaf with prev */
		if (leafprev) {
			leaf_t *this = leafbuf->data;
			leaf_t *that = leafprev->data;
			trace_off(warn("check leaf %p against %p", leafbuf, leafprev););
			trace_off(warn("need = %i, free = %i", (ops->leaf_need)(btree, this), leaf_free(sb, that)););
			/* try to merge leaf with prev */
			if ((ops->leaf_need)(btree, this) <= (ops->leaf_free)(btree, that)) {
				trace_off(warn(">>> can merge leaf %p into leaf %p", leafbuf, leafprev););
				(ops->leaf_merge)(btree, that, this);
				remove_index(path, level);
				set_buffer_dirty(leafprev);
				brelse_free(sb, leafbuf);
				//dirty_buffer_count_check(sb);
				goto keep_prev_leaf;
			}
			brelse(leafprev);
		}
		leafprev = leafbuf;
keep_prev_leaf:

		//nanosleep(&(struct timespec){ 0, 50 * 1000000 }, NULL);
		//printf("time remaining: %Li\n", deadline - gettime());
		if (deadline != -1 && gettime() > deadline)
			suspend = -1;
		if (info->blocks != -1 && freed >= info->blocks)
			suspend = -1;

		/* pop and try to merge finished nodes */
		while (suspend || finished_level(path, level)) {
			/* try to merge node with prev */
			if (prev[level].buffer) {
				assert(level); /* node has no prev */
				struct bnode *this = path_node(path, level);
				struct bnode *that = path_node(prev, level);
				trace_off(warn("check node %p against %p", this, that););
				trace_off(warn("this count = %i prev count = %i", this->count, that->count););
				/* try to merge with node to left */
				if (this->count <= sb->entries_per_node - that->count) {
					trace(warn(">>> can merge node %p into node %p", this, that););
					merge_nodes(that, this);
					remove_index(path, level - 1);
					set_buffer_dirty(prev[level].buffer);
					brelse_free(sb, path[level].buffer);
					//dirty_buffer_count_check(sb);
					goto keep_prev_node;
				}
				brelse(prev[level].buffer);
			}
			prev[level].buffer = path[level].buffer;
keep_prev_node:

			/* deepest key in the path is the resume address */
			if (suspend == -1 && !finished_level(path, level)) {
				suspend = 1; /* only set resume once */
				info->resume = (path[level].next)->key;
			}
			if (!level) { /* remove levels if possible */
				while (levels > 1 && path_node(prev, 0)->count == 1) {
					trace_off(warn("drop btree level"););
					btree->root.block = prev[1].buffer->index;
					brelse_free(sb, prev[0].buffer);
					//dirty_buffer_count_check(sb);
					levels = --btree->root.levels;
					memcpy(prev, prev + 1, levels * sizeof(prev[0]));
					//set_sb_dirty(sb);
				}
				brelse(leafprev);
				release_path(prev, levels);
				//sb->snapmask &= ~snapmask; delete_snapshot_from_disk();
				//set_sb_dirty(sb);
				//save_sb(sb);
				return suspend;
			}

			level--;
			trace_off(printf("pop to level %i, %i of %i nodes\n", level, path[level].next - path_node(path, level)->entries, path_node(path, level)->count););
		}

		/* push back down to leaf level */
		while (level < levels - 1) {
			struct buffer *buffer = bread(sb->devmap, path[level++].next++->block);
			if (!buffer) {
				brelse(leafprev);
				release_path(path, level - 1);
				return -ENOMEM;
			}
			path[level].buffer = buffer;
			path[level].next = buffer->data;
			trace_off(printf("push to level %i, %i nodes\n", level, path_node(path, level)->count););
		};
		//dirty_buffer_count_check(sb);

		/* go to next leaf */
		if (!(leafbuf = bread(sb->devmap, path[level].next++->block))) {
			release_path(path, level);
			return -ENOMEM;
		}
	}
}

/* Insertion */

static void add_child(struct bnode *node, struct index_entry *p, block_t child, u64 childkey)
{
	vecmove(p + 1, p, node->entries + node->count - p);
	p->block = child;
	p->key = childkey;
	node->count++;
}

int insert_child(struct btree *btree, u64 childkey, block_t childblock, struct path path[])
{
	trace(printf("insert child with key %Lu, tree levels %i\n", (L)childkey, btree->levels);)
	int levels = btree->root.levels;
	while (levels--) {
		struct index_entry *next = path[levels].next;
		struct buffer *parentbuf = path[levels].buffer;
		struct bnode *parent = parentbuf->data;

		/* insert and exit if not full */
		if (parent->count < btree->sb->entries_per_node) {
			add_child(parent, next, childblock, childkey);
			set_buffer_dirty(parentbuf);
			return 0;
		}

		/* split a full index node */
		struct buffer *newbuf = new_node(btree);
		if (!newbuf) 
			return -ENOMEM;
		struct bnode *newnode = newbuf->data;
		unsigned half = parent->count / 2;
		u64 newkey = parent->entries[half].key;
		newnode->count = parent->count - half;
		memcpy(&newnode->entries[0], &parent->entries[half], newnode->count * sizeof(struct index_entry));
		parent->count = half;

		/* if the path is in the new node, use that as the parent */
		if (next > parent->entries + half) {
			next = next - &parent->entries[half] + newnode->entries;
			set_buffer_dirty(parentbuf);
			parentbuf = newbuf;
			parent = newnode;
		} else set_buffer_dirty(newbuf);
		add_child(parent, next, childblock, childkey);
		set_buffer_dirty(parentbuf);
		childkey = newkey;
		childblock = newbuf->index;
		brelse(newbuf);
	}
	trace(printf("add tree level\n");)
	struct buffer *newbuf = new_node(btree);
	if (!newbuf)
		return -ENOMEM;
	struct bnode *newroot = newbuf->data;
	newroot->count = 2;
	newroot->entries[0].block = btree->root.block;
	newroot->entries[1].key = childkey;
	newroot->entries[1].block = childblock;
	btree->root.block = newbuf->index;
	vecmove(path + 1, path, btree->root.levels++ + 1);
	path[0] = (struct path){ .buffer = newbuf }; // .next = ???
	//set_sb_dirty(sb);
	set_buffer_dirty(newbuf);
	return 0;
}

void *tree_expand(struct btree *btree, tuxkey_t key, unsigned more, struct path path[])
{
	struct buffer *leafbuf = path[btree->root.levels].buffer;
	struct btree_ops *ops = btree->ops;
	set_buffer_dirty(leafbuf);
	void *space = (ops->leaf_expand)(btree, leafbuf->data, key, more);
	if (space)
		return space;
	trace(warn("split leaf");)
	struct buffer *newbuf = new_leaf(btree);
	if (!newbuf) 
		return NULL; // !!! err_ptr(ENOMEM) this is the right thing to do???
	u64 newkey = (ops->leaf_split)(btree, leafbuf->data, newbuf->data, key);
	block_t childblock = newbuf->index;
	trace_off(warn("use upper? %Li %Li", key, newkey);)
	if (key >= newkey) {
		struct buffer *swap = leafbuf;
		leafbuf = path[btree->root.levels].buffer = newbuf;
		newbuf = swap;
	}
	brelse_dirty(newbuf);
	space = (ops->leaf_expand)(btree, leafbuf->data, key, more);
	assert(space);
	int err = insert_child(btree, newkey, childblock, path);
	if (err) {
		warn("insert_child failed (%s)", strerror(-err));
		return NULL;
	}
	return space;
}

struct btree new_btree(SB, struct btree_ops *ops)
{
	struct btree btree = { .sb = sb, .ops = ops };
	struct buffer *rootbuf = new_node(&btree);
	struct buffer *leafbuf = new_leaf(&btree);
	struct bnode *root = rootbuf->data;
	root->entries[0].block = leafbuf->index;
	root->count = 1;
	btree.root = (struct diskroot){ .block = rootbuf->index, .levels = 1 };
	printf("root at %Li\n", rootbuf->index);
	printf("leaf at %Li\n", leafbuf->index);
	brelse_dirty(rootbuf);
	brelse_dirty(leafbuf);
	return btree;
}

#ifndef main
struct uleaf { u32 magic, count; struct entry { u32 key, val; } entries[]; };

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
	struct entry *limit = leaf->entries + leaf->count;
	for (struct entry *entry = leaf->entries; entry < limit; entry++)
		printf(" %x:%x", entry->key, entry->val);
	printf(" (%x free)\n", uleaf_free(btree, leaf));
}

tuxkey_t uleaf_split(BTREE, vleaf *from, vleaf *into, tuxkey_t key)
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

void *uleaf_expand(BTREE, vleaf *data, tuxkey_t key, unsigned more)
{
	assert(uleaf_sniff(btree, data));
	struct uleaf *leaf = data;
	if (uleaf_free(btree, leaf) < more)
		return NULL;
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	printf("expand leaf at 0x%x by %i\n", at, more);
	vecmove(leaf->entries + at + more, leaf->entries + at, leaf->count++ - at);
	return leaf->entries + at;
}

void uleaf_merge(BTREE, vleaf *into, vleaf *from)
{
}

struct btree_ops ops = {
	.leaf_sniff = uleaf_sniff,
	.leaf_init = uleaf_init,
	.leaf_split = uleaf_split,
	.leaf_expand = uleaf_expand,
	.leaf_dump = uleaf_dump,
	.leaf_need = uleaf_need,
	.leaf_free = uleaf_free,
	.leaf_merge = uleaf_merge,
	.balloc = balloc,
};

block_t balloc(SB)
{
	return sb->nextalloc++;
}

int uleaf_insert(BTREE, struct uleaf *leaf, unsigned key, unsigned val)
{
	printf("insert 0x%x -> 0x%x\n", key, val);
	struct entry *entry = uleaf_expand(btree, leaf, key, 1);
	if (!entry)
		return 1; // need to expand
	assert(entry);
	*entry = (struct entry){ .key = key, .val = val };
	return 0;
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 6 };
	struct map *map = new_map(dev, NULL);
	SB = &(struct sb){ .devmap = map, .blocksize = 1 << dev->bits };
	map->inode = &(struct inode){ .sb = sb, .map = map };
	init_buffers(dev, 1 << 20);
	sb->entries_per_node = (sb->blocksize - offsetof(struct bnode, entries)) / sizeof(struct index_entry);
	printf("entries_per_node = %i\n", sb->entries_per_node);
	struct btree btree = new_btree(sb, &ops);
	btree.entries_per_leaf = (sb->blocksize - offsetof(struct uleaf, entries)) / sizeof(struct entry);

	if (0) {
		struct buffer *buffer = new_leaf(&btree);
		for (int i = 0; i < 7; i++)
			uleaf_insert(&btree, buffer->data, i, i + 0x100);
		uleaf_dump(&btree, buffer->data);
		return 0;
	}

	struct path path[30];
	for (int key = 0; key < 30; key++) {
		if (probe(&btree, key, path))
			error("probe for %i failed", key);
		struct entry *entry = tree_expand(&btree, key, 1, path);
		*entry = (struct entry){ .key = key, .val = key + 0x100 };
		release_path(path, btree.root.levels + 1);
	}
	show_tree_range(&btree, 0, -1);
	return 0;
}
#endif
