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
 * Backend functions
 */

/* Apply hole extents to dtree */
int tux3_flush_hole(struct inode *inode, unsigned delta)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct inode_delta_dirty *i_ddc = tux3_inode_ddc(inode, delta);
	struct hole_extent *hole, *safe;
	int err = 0;

	/*
	 * This is called by backend, it means ->dirty_holes should be
	 * stable. So, we don't need lock for dirty_holes list.
	 */
	list_for_each_entry_safe(hole, safe, &i_ddc->dirty_holes, dirty_list) {
		int ret;

		assert(hole->start + hole->count == MAX_BLOCKS);
		/* FIXME: we would want to delay to free blocks */
		ret = dtree_chop(&tuxnode->btree, hole->start, TUXKEY_LIMIT);
		if (ret && !err)
			err = ret;		/* FIXME: error handling */

		/*
		 * Hole extent was applied to btree. Remove from
		 * ->hole_extents list.
		 */
		spin_lock(&tuxnode->hole_extents_lock);
		list_del_init(&hole->list);
		spin_unlock(&tuxnode->hole_extents_lock);

		list_del_init(&hole->dirty_list);
		tux3_destroy_hole(hole);
	}

	return err;
}

/*
 * Frontend functions
 */

/*
 * Add new hole extent.
 *
 * Find holes, and merge if possible (caller must hold ->i_mutex)
 * FIXME: we can use RCU for this?
 * FIXME: list doesn't scale, use better algorithm
 */
static int tux3_add_hole(struct inode *inode, block_t start, block_t count)
{
	unsigned delta = tux3_get_current_delta();
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct inode_delta_dirty *i_ddc = tux3_inode_ddc(inode, delta);
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

/* Clear hole extents for frontend (called from tux3_purge_inode()) */
int tux3_clear_hole(struct inode *inode, unsigned delta)
{
	struct inode_delta_dirty *i_ddc = tux3_inode_ddc(inode, delta);
	struct hole_extent *hole, *safe;
	int has_hole = 0;

	/* This is iput path, so we don't need locks. */
	list_for_each_entry_safe(hole, safe, &i_ddc->dirty_holes, dirty_list) {
		list_del_init(&hole->dirty_list);
		list_del_init(&hole->list);

		tux3_destroy_hole(hole);

		has_hole = 1;
	}

	return has_hole;
}

/* Is the region a hole? */
static int tux3_is_hole(struct inode *inode, block_t start, unsigned count)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct hole_extent *hole;
	int whole = 0;

	spin_lock(&tuxnode->hole_extents_lock);
	list_for_each_entry(hole, &tuxnode->hole_extents, list) {
		/* FIXME: for now, support truncate only */
		assert(hole->start + hole->count == MAX_BLOCKS);

		if (hole->start <= start) {
			whole = 1;
			break;
		}
	}
	spin_unlock(&tuxnode->hole_extents_lock);

	return whole;
}

/* Update specified segs[] with holes. */
static int tux3_map_hole(struct inode *inode, block_t start, unsigned count,
			 struct block_segment seg[], unsigned segs,
			 unsigned max_segs)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct hole_extent *hole;
	block_t hole_start = MAX_BLOCKS;
	int i;

	/* Search start of hole */
	spin_lock(&tuxnode->hole_extents_lock);
	list_for_each_entry(hole, &tuxnode->hole_extents, list) {
		/* FIXME: for now, support truncate only */
		assert(hole->start + hole->count == MAX_BLOCKS);

		hole_start = min(hole_start, hole->start);
	}
	spin_unlock(&tuxnode->hole_extents_lock);

	/* Outside of hole */
	if (start + count <= hole_start)
		return segs;

	/* Update seg[] */
	for (i = 0; i < segs; i++) {
		/* Matched start of hole */
		if (hole_start < start + seg[i].count) {
			if (seg[i].state == BLOCK_SEG_HOLE) {
				/* Expand if hole */
				seg[i].count = count;
				i++;
			} else {
				/* Update region */
				seg[i].count = hole_start - start;
				i++;

				/* If there is space, add hole region */
				if (i < max_segs) {
					seg[i].state = BLOCK_SEG_HOLE;
					seg[i].block = 0;
					seg[i].count = count;
					i++;
				}
			}
			break;
		}
		start += seg[i].count;
		count -= seg[i].count;
	}

	return i;
}
