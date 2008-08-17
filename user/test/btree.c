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
	trace(printf("new leaf\n"););
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
	trace(printf("new node\n"););
	struct buffer *buffer = new_block(sb, ops); 
	if (!buffer)
		return buffer;
	memset(buffer->data, 0, bufsize(buffer));
	struct bnode *node = buffer->data;
	node->count = 0;
	set_buffer_dirty(buffer);
	return buffer;
}

static struct buffer *blockread(SB, block_t block)
{
	return bread(sb->devmap, block);
}

struct treepath { struct buffer *buffer; struct index_entry *next; };
struct leafpath { struct buffer *buffer; void *object; };

/*
 * A btree path for a btree of depth N consists of N treepath entries
 * and one pathleaf entry.  After a probe the treepath->next fields
 * point at the next entry that will be accessed if the path is
 * advanced, which seemed to work out better than pointing right at
 * the element accessed, particularly for mass delete.  On the other
 * hand, the leaf object points right at the object.
 */

static inline struct bnode *path_node(struct treepath path[], int level)
{
	return (struct bnode *)path[level].buffer;
}

static void brelse_path(struct treepath *path, int levels)
{
	for (int i = 0; i < levels; i++)
		brelse(path[i].buffer);
}

static int probe(SB, struct btree *root, tuxkey_t target, struct treepath *path, struct btree_ops *ops)
{
	unsigned i, levels = root->levels;
	struct buffer *buffer = blockread(sb, root->index);
	if (!buffer)
		return -EIO;
	struct bnode *node = buffer->data;

	for (i = 0; i < levels; i++) {
		struct index_entry *next = node->entries, *top = next + node->count;
		while (++next < top) /* binary search goes here */
			if (next->key > target)
				break;
		path[i] = (struct treepath){ buffer, next };
		if (!(buffer = blockread(sb, (next - 1)->block)))
			goto eek;
		node = (struct bnode *)buffer->data;
	}
	assert((ops->leaf_sniff)(sb, buffer->data));
	path[levels] = (struct treepath){ buffer };
	return 0;
eek:
	brelse_path(path, i - 1);
	return -EIO; /* stupid, it might have been NOMEM */
}

static void show_leaf_range(struct btree_ops *ops, struct buffer *buffer, block_t start, block_t finish)
{
	(ops->leaf_dump)(buffer->map->inode->sb, buffer->data);
}

static void show_subtree_range(SB, struct btree_ops *ops, struct bnode *node, block_t start, block_t finish, int levels, int indent)
{
	int i;

	for (i = 0; i < node->count; i++) {
		struct buffer *buffer = blockread(sb, node->entries[i].block);
		if (levels)
			show_subtree_range(sb, ops, buffer->data, start, finish, levels - 1, indent + 3);
		else {
			show_leaf_range(ops, buffer, start, finish);
		}
		brelse(buffer);
	}
}

void show_tree_range(SB, struct btree_ops *ops, struct btree *root, block_t start, block_t finish)
{
	struct buffer *buffer = blockread(sb, root->index);
	if (!buffer)
		return;
	show_subtree_range(sb, ops, buffer->data, start, finish, root->levels - 1, 0);
	brelse(buffer);
}

void show_tree(SB, struct btree_ops *ops)
{
	show_tree_range(sb, ops, &sb->image.iroot, 0, -1);
}

/* Deletion */

static void remove_index(struct treepath path[], int level)
{
	struct bnode *node = path_node(path, level);
	int count = node->count, i;

	// stomps the node count (if 0th key holds count)
	memmove(path[level].next - 1, path[level].next,
		(char *)&node->entries[count] - (char *)path[level].next);
	node->count = count - 1;
	--(path[level].next);
	set_buffer_dirty(path[level].buffer);

	// no pivot for last entry
	if (path[level].next == node->entries + node->count)
		return;

	// climb up to common parent and set pivot to deleted key
	// what if index is now empty? (no deleted key)
	// then some key above is going to be deleted and used to set pivot
	if (path[level].next == node->entries && level) {
		block_t pivot = (path[level].next)->key;
		/* climb the path while at first entry */
		for (i = level - 1; path[i].next - 1 == path_node(path, i)->entries; i--)
			if (!i) /* bail out at root */
				return;
		/* found the node with the old pivot, set it to deleted key */
		(path[i].next - 1)->key = pivot;
		set_buffer_dirty(path[i].buffer);
	}
}

static void merge_nodes(struct bnode *node, struct bnode *node2)
{
	memcpy(&node->entries[node->count], &node2->entries[0], node2->count * sizeof(struct index_entry));
	node->count += node2->count;
}

static void brelse_free(SB, struct buffer *buffer)
{
	brelse(buffer);
	if (buffer->count) {
		warn("free block %Lx still in use!", (long long)buffer->index);
		return;
	}
	free_block(sb, buffer->index);
	set_buffer_empty(buffer);
}

static inline int finished_level(struct treepath path[], int level)
{
	struct bnode *node = path_node(path, level);
	return path[level].next == node->entries + node->count;
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
	struct treepath path[levels + 1], prev[levels + 1];
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
				if (this->count <= sb->alloc_per_node - that->count) {
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
			struct buffer *buffer = blockread(sb, path[level++].next++->block);
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
		if (!(leafbuf = blockread(sb, path[level].next++->block))) {
			brelse_path(path, level);
			return -ENOMEM;
		}
	}
}

/* Insertion */

static void add_child(struct bnode *node, struct index_entry *p, block_t child, u64 childkey)
{
	memmove(p + 1, p, (char *)(&node->entries[0] + node->count) - (char *)p);
	p->block = child;
	p->key = childkey;
	node->count++;
}

int insert_child(SB, struct btree *root, u64 childkey, block_t childblock, struct treepath path[], struct btree_ops *ops)
{
	int levels = root->levels;
	while (levels--) {
		struct index_entry *next = path[levels].next;
		struct buffer *parentbuf = path[levels].buffer;
		struct bnode *parent = parentbuf->data;

		/* insert and exit if not full */
		if (parent->count < sb->alloc_per_node) {
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
	root->levels++;
	//set_sb_dirty(sb);
	brelse_dirty(newbuf);
	return 0;
}

void *tree_expand(SB, struct btree *root, u64 target, unsigned size, struct treepath path[], unsigned levels, struct btree_ops *ops)
{
	struct buffer *leafbuf = path[levels].buffer;
	set_buffer_dirty(leafbuf);
	void *space = (ops->leaf_expand)(sb, leafbuf->data, target, size);
	if (space)
		return space;

	trace(warn("split leaf");)
	struct buffer *childbuf = new_leaf(sb, ops);
	if (!childbuf) 
		return NULL; // !!! err_ptr(ENOMEM) this is the right thing to do???
	u64 childkey = (ops->leaf_split)(sb, leafbuf->data, childbuf->data, 0);
	block_t childblock = childbuf->index;
	if (target < childkey) {
		struct buffer *swap = leafbuf;
		leafbuf = childbuf;
		childbuf = swap;
	}
	brelse_dirty(childbuf);
	space = (ops->leaf_expand)(sb, leafbuf->data, target, size);
	assert(space);
	insert_child(sb, root, childkey, childblock, path, ops); // !!! error return?
	return space;
}

int tuxread(struct inode *inode, block_t target, char *data, unsigned len)
{
	struct buffer *blockbuf = bread(inode->map, target);
	if (!blockbuf)
		return -EIO;
	memcpy(data, blockbuf->data, len);
	brelse(blockbuf);
	return 0;
}

int tuxwrite(struct inode *inode, block_t target, char *data, unsigned len)
{
	struct buffer *blockbuf = getblk(inode->map, target);
	if (!blockbuf)
		return -EIO;
	memcpy(blockbuf->data, data, len);
	set_buffer_dirty(blockbuf);
	brelse(blockbuf);
	return 0;
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

int main(int argc, char *argv[])
{
	return 0;
}
