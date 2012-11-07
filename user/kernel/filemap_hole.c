/*
 * Hole extents functions
 *
 * The hole extents works as middle layer of page cache and dtree.
 *
 * When read data, frontend checks page cache at first. Then, if there is
 * no page cache, it lookups dtree to get address of data.
 *
 * To delay truncate of dtree, this adds the hole extents for
 * truncated region before looking up dtree, like delayed
 * allocation. With this, frontend doesn't lookup dtree if there is
 * the hole extents.
 *
 * And backend will apply the hole extents to dtree later, and do
 * actual truncation and freeing blocks.
 */

#include "tux3.h"
#include "filemap_hole.h"

/* Extent to represent the dirty hole */
struct hole_extent {
	struct list_head list;		/* link for ->hole_extents */
	struct list_head dirty_list;	/* link for ->dirty_holes */
	block_t start;			/* start block of hole */
	block_t count;			/* number of blocks of hole */
};

static struct kmem_cache *tux_hole_cachep;

static void tux3_hole_init_once(void *mem)
{
	struct hole_extent *hole = mem;

	INIT_LIST_HEAD(&hole->list);
	INIT_LIST_HEAD(&hole->dirty_list);
}

int __init tux3_init_hole_cache(void)
{
	tux_hole_cachep = kmem_cache_create("tux3_hole_cache",
			sizeof(struct hole_extent), 0,
			(SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
			tux3_hole_init_once);
	if (tux_hole_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void tux3_destroy_hole_cache(void)
{
	kmem_cache_destroy(tux_hole_cachep);
}

#if 0
static struct hole_extent *tux3_alloc_hole(void)
{
	struct hole_extent *hole;

	hole = kmem_cache_alloc(tux_hole_cachep, GFP_NOFS);
	if (!hole)
		return NULL;

	return hole;
}

static void tux3_destroy_hole(struct hole_extent *hole)
{
	assert(list_empty(&hole->list));
	assert(list_empty(&hole->dirty_list));
	kmem_cache_free(tux_hole_cachep, hole);
}
#endif
