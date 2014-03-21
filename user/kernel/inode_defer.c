/*
 * Deferred inum allocation management.
 *
 * This uses bitmap to find current in-flight deferred inum
 * allocation.  For each the node represent BITMAP_SIZE bits, and the
 * node is hashed on struct tux3_idefer_map.
 */

/* Bitmap node hash size */
#define NODE_HASH_BITS		8
#define NODE_HASH_SIZE		(1 << NODE_HASH_BITS)

/* Bitmap size in byte and bit */
#define BITMAP_BYTE_SHIFT	6
#define BITMAP_BYTE_SIZE	(1 << BITMAP_BYTE_SHIFT)
#define BITMAP_SHIFT		(BITMAP_BYTE_SHIFT + 3)
#define BITMAP_SIZE		(1 << BITMAP_SHIFT)
#define BITMAP_MASK		(BITMAP_SIZE - 1)

struct tux3_idefer_map {
	struct hlist_head heads[NODE_HASH_SIZE];
};

struct tux3_idefer_node {
	struct hlist_node link;
	block_t index;
	unsigned count;
	unsigned long bitmap[BITMAP_SIZE / sizeof(unsigned long)];
};

static struct kmem_cache *tux3_idefer_node_cachep;

struct tux3_idefer_map *tux3_alloc_idefer_map(void)
{
	struct tux3_idefer_map *map;

	map = malloc(sizeof(*map));
	if (map) {
		int i;
		for (i = 0; i < NODE_HASH_SIZE; i++)
			INIT_HLIST_HEAD(&map->heads[i]);
	}
	return map;
}

void tux3_free_idefer_map(struct tux3_idefer_map *map)
{
	if (map) {
		int i;
		for (i = 0; i < NODE_HASH_SIZE; i++)
			assert(hlist_empty(&map->heads[i]));
		free(map);
	}
}

static void tux3_idefer_init_once(void *mem)
{
	struct tux3_idefer_node *node = mem;

	INIT_HLIST_NODE(&node->link);
	node->count = 0;
	memset(node->bitmap, 0, sizeof(node->bitmap));
}

int __init tux3_init_idefer_cache(void)
{
	tux3_idefer_node_cachep = kmem_cache_create("tux3_idefer_node",
				  sizeof(struct tux3_idefer_node), 0,
				  (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
				  tux3_idefer_init_once);
	if (tux3_idefer_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void tux3_destroy_idefer_cache(void)
{
	kmem_cache_destroy(tux3_idefer_node_cachep);
}

static struct tux3_idefer_node *idefer_alloc_node(block_t index)
{
	struct tux3_idefer_node *node;

	node = kmem_cache_alloc(tux3_idefer_node_cachep, GFP_NOFS);
	if (!node)
		return NULL;

	node->index = index;

	return node;
}

static void idefer_free_node(struct tux3_idefer_node *node)
{
	kmem_cache_free(tux3_idefer_node_cachep, node);
}

static inline unsigned idefer_hash(block_t index)
{
	return hash_64(index, NODE_HASH_BITS);
}

static struct tux3_idefer_node *
idefer_find_node(struct hlist_head *head, block_t index,
		 struct hlist_node **prev)
{
	struct tux3_idefer_node *node;

	if (prev)
		*prev = NULL;

	hlist_for_each_entry(node, head, link) {
		if (node->index < index) {
			if (prev)
				*prev = &node->link;
			continue;
		}
		if (node->index == index)
			return node;
		if (node->index > index)
			return NULL;
	}

	return NULL;
}

/* Set a bit for deferred inum */
static int tux3_idefer_add(struct tux3_idefer_map *map, inum_t inum)
{
	block_t index = inum >> BITMAP_SHIFT;
	unsigned offset = inum & BITMAP_MASK;
	struct hlist_head *head = map->heads + idefer_hash(index);
	struct tux3_idefer_node *node;
	struct hlist_node *prev = NULL;

	node = idefer_find_node(head, index, &prev);
	if (!node) {
		node = idefer_alloc_node(index);
		if (!node)
			return -ENOMEM;
		if (prev)
			hlist_add_after(prev, &node->link);
		else
			hlist_add_head(&node->link, head);
	}

	assert(!test_bit(offset, node->bitmap));
	__set_bit(offset, node->bitmap);
	node->count++;

	return 0;
}

/* Clear a bit for deferred inum */
static void tux3_idefer_del(struct tux3_idefer_map *map, inum_t inum)
{
	block_t index = inum >> BITMAP_SHIFT;
	unsigned offset = inum & BITMAP_MASK;
	struct hlist_head *head = map->heads + idefer_hash(index);
	struct tux3_idefer_node *node;

	node = idefer_find_node(head, index, NULL);
	assert(node);
	assert(test_bit(offset, node->bitmap));
	__clear_bit(offset, node->bitmap);
	node->count--;

	if (node->count == 0) {
		hlist_del(&node->link);
		idefer_free_node(node);
	}
}

/* Find free inum except deferred inums from specified range */
static inum_t find_free(struct tux3_idefer_map *map, inum_t inum, inum_t limit)
{
	block_t limit_index = (limit + BITMAP_MASK) >> BITMAP_SHIFT;
	block_t index = inum >> BITMAP_SHIFT;
	unsigned offset = inum & BITMAP_MASK;

	while (index < limit_index) {
		struct hlist_head *head = map->heads + idefer_hash(index);
		struct tux3_idefer_node *node;

		node = idefer_find_node(head, index, NULL);
		if (!node)
			goto found;

		if (node->count != BITMAP_SIZE) {
			offset = find_next_zero_bit(node->bitmap, BITMAP_SIZE,
						    offset);
			if (offset < BITMAP_SIZE)
				goto found;
		}

		index++;
		offset = 0;
	}

	return TUX_INVALID_INO;

found:
	return (index << BITMAP_SHIFT) + offset;
}

/* Find free inum except deferred inums */
static inum_t tux3_idefer_find_free(struct tux3_idefer_map *map, inum_t start)
{
	inum_t inum;

	inum = find_free(map, start, TUXKEY_LIMIT);
	if (inum == TUX_INVALID_INO)
		inum = find_free(map, TUX_NORMAL_INO, start);

	assert(inum != TUX_INVALID_INO);
	return inum;
}
