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

#define trace trace_on

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

static struct buffer *new_block(SB, struct btree_ops *ops)
{
        return getblk(sb->devmap, (ops->balloc)(sb));
}

static struct buffer *new_leaf(SB, struct btree_ops *ops)
{
	struct buffer *buffer = new_block(sb, ops); 
	if (!buffer)
		return NULL;
	memset(buffer->data, 0, bufsize(buffer));
	(ops->leaf_init)(sb, buffer->data);
	set_buffer_dirty(buffer);
	return buffer;
}

static struct buffer *new_node(SB, struct btree_ops *ops)
{
	struct buffer *buffer = new_block(sb, ops); 
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

static void brelse_path(struct path *path, int levels)
{
	for (int i = 0; i < levels; i++)
		brelse(path[i].buffer);
}

static int probe(SB, struct btree *root, tuxkey_t key, struct path *path, struct btree_ops *ops)
{
	unsigned i, levels = root->levels;
	struct buffer *buffer = bread(sb->devmap, root->index);
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
		if (!(buffer = bread(sb->devmap, (next - 1)->block)))
			goto eek;
		node = (struct bnode *)buffer->data;
	}
	assert((ops->leaf_sniff)(sb, buffer->data));
	path[levels] = (struct path){ buffer };
	return 0;
eek:
	brelse_path(path, i - 1);
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
		if (!(buffer = bread(map, path[level++].next++->block)))
			goto eek;
		node = buffer->data;
		path[level] = (struct path){ .buffer = buffer, .next = node->entries };
	} while (level < levels);
	return 1;
eek:
	brelse_path(path, level);
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

void show_tree_range(SB, struct btree_ops *ops, struct btree *root, tuxkey_t start, unsigned count)
{
	printf("%i level btree %p at %Li:\n", root->levels, root, (L)root->index);
	struct path path[30]; // check for overflow!!!
	if (probe(sb, root, start, path, ops))
		error("probe failed for some unknown reason"); // probe should return error!!!
	struct buffer *buffer;
	do {
		buffer = path[root->levels].buffer;
		assert((ops->leaf_sniff)(sb, buffer->data));
		(ops->leaf_dump)(sb, buffer->data);
		//tuxkey_t *next = next_key(path, root->levels);
		//printf("next key = %Lx:\n", next ? (L)*next : 0);
	} while (--count && advance(buffer->map, path, root->levels));
}

void show_tree(SB, struct btree_ops *ops)
{
	show_tree_range(sb, ops, &sb->image.iroot, 0, -1);
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

int delete_tree_partial(SB, struct btree_ops *ops, struct btree *root, struct delete_info *info, millisecond_t deadline, int maxblocks)
{
	int levels = root->levels, level = levels - 1, suspend = 0, freed = 0;
	struct path path[levels + 1], prev[levels + 1];
	struct buffer *leafbuf, *leafprev = NULL;
	memset(path, 0, sizeof(path));

	probe(sb, root, info->resume, path, ops);
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
			trace_off(warn("need = %i, free = %i", (ops->leaf_need)(sb, this), leaf_free(sb, that)););
			/* try to merge leaf with prev */
			if ((ops->leaf_need)(sb, this) <= (ops->leaf_free)(sb, that)) {
				trace_off(warn(">>> can merge leaf %p into leaf %p", leafbuf, leafprev););
				(ops->leaf_merge)(sb, that, this);
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
				assert(level); /* root has no prev */
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
					root->index = prev[1].buffer->index;
					brelse_free(sb, prev[0].buffer);
					//dirty_buffer_count_check(sb);
					levels = --root->levels;
					memcpy(prev, prev + 1, levels * sizeof(prev[0]));
					//set_sb_dirty(sb);
				}
				brelse(leafprev);
				brelse_path(prev, levels);
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
				brelse_path(path, level - 1);
				return -ENOMEM;
			}
			path[level].buffer = buffer;
			path[level].next = buffer->data;
			trace_off(printf("push to level %i, %i nodes\n", level, path_node(path, level)->count););
		};
		//dirty_buffer_count_check(sb);

		/* go to next leaf */
		if (!(leafbuf = bread(sb->devmap, path[level].next++->block))) {
			brelse_path(path, level);
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

int insert_child(SB, struct btree *root, u64 childkey, block_t childblock, struct path path[], struct btree_ops *ops)
{
	printf("insert child with key %Lu, tree levels %i\n", (L)childkey, root->levels);
	int levels = root->levels;
	while (levels--) {
		struct index_entry *next = path[levels].next;
		struct buffer *parentbuf = path[levels].buffer;
		struct bnode *parent = parentbuf->data;

		/* insert and exit if not full */
		if (parent->count < sb->entries_per_node) {
			add_child(parent, next, childblock, childkey);
			set_buffer_dirty(parentbuf);
			return 0;
		}

		/* split a full index node */
		struct buffer *newbuf = new_node(sb, ops);
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
	struct buffer *newbuf = new_node(sb, ops);
	if (!newbuf)
		return -ENOMEM;
	struct bnode *newroot = newbuf->data;
	newroot->count = 2;
	newroot->entries[0].block = root->index;
	newroot->entries[1].key = childkey;
	newroot->entries[1].block = childblock;
	root->index = newbuf->index;
	vecmove(path + 1, path, root->levels++ + 1);
	path[0] = (struct path){ .buffer = newbuf }; // .next = ???
	//set_sb_dirty(sb);
	set_buffer_dirty(newbuf);
	return 0;
}

void *tree_expand(SB, struct btree *root, tuxkey_t key, unsigned more, struct path path[], struct btree_ops *ops)
{
	struct buffer *leafbuf = path[root->levels].buffer;
	set_buffer_dirty(leafbuf);
	void *space = (ops->leaf_expand)(sb, leafbuf->data, key, more);
	if (space)
		return space;
	trace(warn("split leaf");)
	struct buffer *newbuf = new_leaf(sb, ops);
	if (!newbuf) 
		return NULL; // !!! err_ptr(ENOMEM) this is the right thing to do???
	u64 newkey = (ops->leaf_split)(sb, leafbuf->data, newbuf->data, key);
	block_t childblock = newbuf->index;
	trace_off(warn("use upper? %Li %Li", key, newkey);)
	if (key >= newkey) {
		struct buffer *swap = leafbuf;
		leafbuf = path[root->levels].buffer = newbuf;
		newbuf = swap;
	}
	brelse_dirty(newbuf);
	space = (ops->leaf_expand)(sb, leafbuf->data, key, more);
	assert(space);
	int err = insert_child(sb, root, newkey, childblock, path, ops);
	if (err) {
		warn("insert_child failed (%s)", strerror(-err));
		return NULL;
	}
	return space;
}

struct btree new_btree(SB, struct btree_ops *ops)
{
	struct buffer *rootbuf = new_node(sb, ops);
	struct buffer *leafbuf = new_leaf(sb, ops);
	struct bnode *root = rootbuf->data;
	root->entries[0].block = leafbuf->index;
	root->count = 1;
	struct btree btree = { .index = rootbuf->index, .levels = 1 };
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

int uleaf_sniff(SB, vleaf *leaf)
{
	return to_uleaf(leaf)->magic == 0xc0de;
}

int uleaf_init(SB, vleaf *leaf)
{
	*to_uleaf(leaf) = (struct uleaf){ .magic = 0xc0de };
	return 0;
}

unsigned uleaf_need(SB, vleaf *leaf)
{
	return to_uleaf(leaf)->count;
}

unsigned uleaf_free(SB, vleaf *leaf)
{
	unsigned max_entries = (struct entry *)(leaf + sb->blocksize) - to_uleaf(leaf)->entries;
	return max_entries - to_uleaf(leaf)->count;
}

void uleaf_dump(SB, vleaf *data)
{
	struct uleaf *leaf = data;
	printf("leaf %p/%i:", leaf, leaf->count);
	struct entry *limit = leaf->entries + leaf->count;
	for (struct entry *entry = leaf->entries; entry < limit; entry++)
		printf(" %x->%x", entry->key, entry->val);
	printf(" (%x free)\n", uleaf_free(sb, leaf));
}

#include "hexdump.c"

tuxkey_t uleaf_split(SB, vleaf *from, vleaf *into, tuxkey_t key)
{
	assert(uleaf_sniff(sb, from));
	struct uleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && key > leaf->entries[leaf->count - 1].key) // binsearch!
		at = leaf->count;
	unsigned tail = leaf->count - at;
	uleaf_init(sb, into);
	veccopy(to_uleaf(into)->entries, leaf->entries + at, tail);
	to_uleaf(into)->count = tail;
	leaf->count = at;
	return at < leaf->count ? to_uleaf(into)->entries[0].key : key;
}

void *uleaf_expand(SB, vleaf *data, tuxkey_t key, unsigned more)
{
	assert(uleaf_sniff(sb, data));
	struct uleaf *leaf = data;
	if (uleaf_free(sb, leaf) < more)
		return NULL;
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	printf("expand leaf at 0x%x by %i\n", at, more);
	vecmove(leaf->entries + at + more, leaf->entries + at, leaf->count++ - at);
	return leaf->entries + at;
}

void uleaf_merge(SB, vleaf *into, vleaf *from)
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

int uleaf_insert(SB, struct uleaf *leaf, unsigned key, unsigned val)
{
	printf("insert 0x%x -> 0x%x\n", key, val);
	struct entry *entry = uleaf_expand(sb, leaf, key, 1);
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

	if (0) {
		struct buffer *buffer = new_leaf(sb, &ops);
		for (int i = 0; i < 7; i++)
			uleaf_insert(sb, buffer->data, i, i + 0x100);
		uleaf_dump(sb, buffer->data);
		return 0;
	}

	struct btree btree = new_btree(sb, &ops);
	struct path path[30];
	for (int i = 0; i < 30; i++) {
		int key = i;
		if (probe(sb, &btree, key, path, &ops))
			error("probe for %i failed", key);
		struct entry *entry = tree_expand(sb, &btree, key, 1, path, &ops);
		*entry = (struct entry){ .key = key, .val = key + 0x100 };
		brelse_path(path, btree.levels + 1);
	}
	show_tree_range(sb, &ops, &btree, 0, -1);
	show_buffers(map);
	return 0;
}
#endif
