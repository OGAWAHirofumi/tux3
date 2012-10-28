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

/*
 * Add new hole extent.
 *
 * Find holes, and merge if possible (caller must hold ->i_mutex)
 * FIXME: we can use RCU for this?
 * FIXME: list doesn't scale, use better algorithm
 */
static int tux3_add_hole(struct inode *inode, block_t start, block_t count)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct inode_delta_dirty *i_ddc = tux3_inode_ddc(inode, sb->delta);
	struct hole_extent *hole, *safe, *merged = NULL, *removed = NULL;

	/* FIXME: for now, support truncate only */
	assert(start + count == MAX_BLOCKS);

	/*
	 * Find frontend dirty holes, and merge if possible
	 * (->dirty_holes is protected by ->i_mutex)
	 */
	list_for_each_entry_safe(hole, safe, &i_ddc->dirty_holes, dirty_list) {
		block_t end = start + count;
		/* Can merge? */
		if (end < hole->start || hole->start + hole->count < start)
			continue;

		/* Calculate merged extent */
		start = min(start, hole->start);
		count = max(end, hole->start + hole->count) - start;

		/* Update hole */
		spin_lock(&tuxnode->hole_extents_lock);
		if (!merged)
			merged = hole;
		else {
			/* Remove old hole */
			list_del_init(&hole->dirty_list);
			list_del_init(&hole->list);
			removed = hole;
		}
		merged->start = start;
		merged->count = count;
		spin_unlock(&tuxnode->hole_extents_lock);

		if (removed)
			tux3_destroy_hole(hole);
	}
	if (merged)
		return 0;

	hole = tux3_alloc_hole();
	if (!hole)
		return -ENOMEM;

	hole->start = start;
	hole->count = count;
	list_add(&hole->dirty_list, &i_ddc->dirty_holes);
	/* Add hole */
	spin_lock(&tuxnode->hole_extents_lock);
	list_add(&hole->list, &tux_inode(inode)->hole_extents);
	spin_unlock(&tuxnode->hole_extents_lock);

	return 0;
}

int tux3_add_truncate_hole(struct inode *inode, loff_t newsize)
{
	struct sb *sb = tux_sb(inode->i_sb);
	block_t start = (newsize + sb->blockmask) >> sb->blockbits;

	return tux3_add_hole(inode, start, MAX_BLOCKS - start);
}

/* Clear hole extents for frontend (called from iput path) */
void tux3_clear_hole(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct inode_delta_dirty *i_ddc = tux3_inode_ddc(inode, sb->delta);
	struct hole_extent *hole, *safe;

	/* This is iput path, so we don't need locks. */
	list_for_each_entry_safe(hole, safe, &i_ddc->dirty_holes, dirty_list) {
		list_del_init(&hole->dirty_list);
		list_del_init(&hole->list);

		tux3_destroy_hole(hole);
	}
}
