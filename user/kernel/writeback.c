/*
 * Writeback for inodes
 *
 * lock order:
 *     inode->i_lock
 *         tuxnode->lock
 *         sb->dirty_inodes_lock
 */

#include "tux3.h"
#include "filemap_hole.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: probably, we should rewrite with own buffer management. */

#if I_DIRTY != ((1 << 0) | (1 << 1) | (1 << 2))
#error "I_DIRTY was changed"
#endif

/*
 * inode->flag usage from LSB:
 * - inode dirty flags
 * - iattr flags
 * - xattr flags
 * - delete dirty flags
 * - btree dirty
 * - inode is dead flag
 */

/* I_DIRTY_SYNC, I_DIRTY_DATASYNC, and I_DIRTY_PAGES */
#define NUM_DIRTY_BITS		3
/* Iattr fork dirty base */
#define IATTR_DIRTY		1
/* Xattr fork dirty base */
#define XATTR_DIRTY		1
/* Dead inode dirty base */
#define DEAD_DIRTY		1
/* Bits usage of inode->flags */
#define IFLAGS_DIRTY_BITS	(NUM_DIRTY_BITS * TUX3_MAX_DELTA)
#define IFLAGS_IATTR_BITS	(order_base_2(IATTR_DIRTY + TUX3_MAX_DELTA))
#define IFLAGS_XATTR_BITS	(order_base_2(XATTR_DIRTY + TUX3_MAX_DELTA))
#define IFLAGS_DEAD_BITS	(order_base_2(DEAD_DIRTY + TUX3_MAX_DELTA))
/* Bit shift for inode->flags */
#define IFLAGS_IATTR_SHIFT	IFLAGS_DIRTY_BITS
#define IFLAGS_XATTR_SHIFT	(IFLAGS_IATTR_SHIFT + IFLAGS_IATTR_BITS)
#define IFLAGS_DEAD_SHIFT	(IFLAGS_XATTR_SHIFT + IFLAGS_XATTR_BITS)

/* btree root is modified from only backend, so no need per-delta flag */
#define TUX3_DIRTY_BTREE	(1 << 30)
/* the dead flag is set by only backend, so no need per-delta flag */
#define TUX3_INODE_DEAD		(1 << 31)

static inline unsigned tux3_dirty_shift(unsigned delta)
{
	return tux3_delta(delta) * NUM_DIRTY_BITS;
}

static inline unsigned tux3_dirty_mask(int flags, unsigned delta)
{
	return flags << tux3_dirty_shift(delta);
}

static inline unsigned tux3_dirty_flags(struct inode *inode, unsigned delta)
{
	unsigned flags = tux_inode(inode)->flags;
	unsigned ret;

	ret = (flags >> tux3_dirty_shift(delta)) & I_DIRTY;
	ret |= flags & TUX3_DIRTY_BTREE;
	return ret;
}

/* This is hook of __mark_inode_dirty() and called I_DIRTY_PAGES too */
void tux3_dirty_inode(struct inode *inode, int flags)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned delta = tux3_inode_delta(inode);
	unsigned mask = tux3_dirty_mask(flags, delta);
	struct sb_delta_dirty *s_ddc;
	struct inode_delta_dirty *i_ddc;

	if ((tuxnode->flags & mask) == mask)
		return;

	/*
	 * If inode is bitmap or volmap, delta is different cycle with
	 * sb->delta. So those can race. And those inodes are flushed
	 * by do_commit().
	 *
	 * So, don't bother s_ddc->dirty_inodes by adding those inodes.
	 */
	if (tuxnode->inum == TUX_BITMAP_INO || tuxnode->inum == TUX_VOLMAP_INO)
		s_ddc = NULL;
	else {
		s_ddc = tux3_sb_ddc(sb, delta);
		i_ddc = tux3_inode_ddc(inode, delta);
	}

	spin_lock(&tuxnode->lock);
	if ((tuxnode->flags & mask) != mask) {
		tuxnode->flags |= mask;

		if (s_ddc) {
			spin_lock(&sb->dirty_inodes_lock);
			if (list_empty(&i_ddc->dirty_list))
				list_add_tail(&i_ddc->dirty_list,
					      &s_ddc->dirty_inodes);
			spin_unlock(&sb->dirty_inodes_lock);
		}
	}
	spin_unlock(&tuxnode->lock);
}

/*
 * Called from backend only to mark btree as dirty. (usually from the
 * path of flushing buffers)
 */
void tux3_mark_btree_dirty(struct btree *btree)
{
	if (btree != itable_btree(btree->sb) &&
	    btree != otable_btree(btree->sb)) {
		struct tux3_inode *tuxnode = tux_inode(btree_inode(btree));

		spin_lock(&tuxnode->lock);
		/* FIXME: Frontend modify btree for now, so this is not true */
		//assert(tuxnode->flags);
		tuxnode->flags |= TUX3_DIRTY_BTREE;
		spin_unlock(&tuxnode->lock);
	}
}

#include "writeback_inodedelete.c"
#include "writeback_iattrfork.c"
#include "writeback_xattrfork.c"

/* Clear dirty flags for delta (caller must hold inode->i_lock/tuxnode->lock) */
static void tux3_clear_dirty_inode_nolock(struct inode *inode, unsigned delta,
					  int frontend)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned mask = tux3_dirty_mask(I_DIRTY, delta);
	unsigned old_dirty;

	old_dirty = tuxnode->flags & (TUX3_DIRTY_BTREE | mask);
	/* Clear dirty flags for delta */
	tuxnode->flags &= ~(TUX3_DIRTY_BTREE | mask);
	/* FIXME: Purge inode is from frontend for now, so this is not true */
	//assert(!(old_dirty & TUX3_DIRTY_BTREE) || (old_dirty & mask));

	/* Remove inode from list */
	if (old_dirty) {
		/* Only if called from frontend, we need to lock */
		if (frontend)
			spin_lock(&sb->dirty_inodes_lock);

		list_del_init(&tux3_inode_ddc(inode, delta)->dirty_list);

		if (frontend)
			spin_unlock(&sb->dirty_inodes_lock);
	}

	/* Update inode state */
	if (tuxnode->flags & ~TUX3_INODE_DEAD)
		inode->i_state |= I_DIRTY;
	else
		inode->i_state &= ~I_DIRTY;
}

/* Clear dirty flags for delta */
static void __tux3_clear_dirty_inode(struct inode *inode, unsigned delta)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	spin_lock(&inode->i_lock);
	spin_lock(&tuxnode->lock);
	tux3_clear_dirty_inode_nolock(inode, delta, 0);
	spin_unlock(&tuxnode->lock);
	spin_unlock(&inode->i_lock);
}

/* Clear dirty flags for frontend delta */
void tux3_clear_dirty_inode(struct inode *inode)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	spin_lock(&inode->i_lock);
	spin_lock(&tuxnode->lock);
	tux3_iattr_clear_dirty(tuxnode);
	tux3_clear_dirty_inode_nolock(inode, tux3_inode_delta(inode), 1);
	spin_unlock(&tuxnode->lock);
	spin_unlock(&inode->i_lock);
}

void __tux3_mark_inode_dirty(struct inode *inode, int flags)
{
	/* Call tux3_dirty_inode() for I_DIRTY_PAGES too */
	if ((flags & I_DIRTY) == I_DIRTY_PAGES)
		tux3_dirty_inode(inode, flags);

	__mark_inode_dirty(inode, flags);
}

/*
 * Mark buffer as dirty to flush at delta flush.
 *
 * Specified buffer must be for volmap (i.e. no buffer fork, and
 * page->mapping is valid). Otherwise this will race with buffer fork.
 */
void tux3_mark_buffer_dirty(struct buffer_head *buffer)
{
	struct inode *inode;

	/*
	 * Very *carefully* optimize the it-is-already-dirty case.
	 *
	 * Don't let the final "is it dirty" escape to before we
	 * perhaps modified the buffer.
	 */
	if (buffer_dirty(buffer)) {
		smp_mb();
		if (buffer_dirty(buffer))
			return;
	}

	inode = buffer_inode(buffer);
	assert(inode == tux_sb(inode->i_sb)->volmap); /* must be volmap */

	tux3_set_buffer_dirty(mapping(inode), buffer, TUX3_INIT_DELTA);
	/* FIXME: we need to dirty inode only if buffer became
	 * dirty. However, tux3_set_buffer_dirty doesn't provide it */
	__tux3_mark_inode_dirty(inode, I_DIRTY_PAGES);
}

/*
 * Mark buffer as dirty to flush at rollup flush
 *
 * Specified buffer must be for volmap (i.e. no buffer fork, and
 * page->mapping is valid). Otherwise this will race with buffer fork.
 */
void tux3_mark_buffer_rollup(struct buffer_head *buffer)
{
	struct sb *sb;
	struct inode *inode;

	/*
	 * Very *carefully* optimize the it-is-already-dirty case.
	 *
	 * Don't let the final "is it dirty" escape to before we
	 * perhaps modified the buffer.
	 */
	if (buffer_dirty(buffer)) {
		smp_mb();
		if (buffer_dirty(buffer))
			return;
	}

	inode = buffer_inode(buffer);
	sb = tux_sb(inode->i_sb);
	assert(inode == sb->volmap); /* must be volmap */

	tux3_set_buffer_dirty_list(mapping(inode), buffer, sb->rollup,
				   &sb->rollup_buffers);
}

static void tux3_state_read_and_clear(struct inode *inode,
				      struct tux3_iattr_data *idata,
				      unsigned *deleted,
				      unsigned delta)
{
	struct tux3_inode *tuxnode = tux_inode(inode);

	spin_lock(&tuxnode->lock);

	/* Get iattr data */
	tux3_iattr_read_and_clear(inode, idata, delta);
	/* Check whether inode has to delete */
	tux3_dead_read_and_clear(inode, deleted, delta);

	spin_unlock(&tuxnode->lock);
}

static inline int tux3_flush_buffers(struct inode *inode,
				     struct tux3_iattr_data *idata,
				     unsigned delta)
{
	struct list_head *dirty_buffers = tux3_dirty_buffers(inode, delta);
	int err;

	/* FIXME: error handling */

	/* Apply hole extents before page caches */
	err = tux3_flush_hole(inode, delta);
	if (err)
		return err;

	/* Apply page caches */
	return flush_list(mapping(inode), idata, dirty_buffers);
}

/*
 * Flush inode.
 *
 * The inode dirty flags keeps until finish I/O to prevent inode
 * reclaim. Because we don't wait writeback on evict_inode(), and
 * instead we keeps the inode while writeback is running.
 */
int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	/* FIXME: linux writeback doesn't allow to control writeback
	 * timing. */
	struct tux3_iattr_data idata;
	unsigned dirty, deleted;
	int ret = 0, err;

	trace("inum %Lu", tux_inode(inode)->inum);

	/*
	 * Read the stabled inode attributes and state for this delta,
	 * then tell we read already.
	 */
	tux3_state_read_and_clear(inode, &idata, &deleted, delta);

	err = tux3_flush_buffers(inode, &idata, delta);
	if (err && !ret)
		ret = err;

	/* Get flags after tux3_flush_buffers() to check TUX3_DIRTY_BTREE */
	dirty = tux3_dirty_flags(inode, delta);

	if (dirty & (TUX3_DIRTY_BTREE | I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		/*
		 * If there is btree root, adjust present after
		 * tux3_flush_buffers().
		 */
		tux3_iattr_adjust_for_btree(inode, &idata);

		err = tux3_save_inode(inode, &idata, delta);
		if (err && !ret)
			ret = err;
	}

	/* FIXME: In the error path, dirty state would still be
	 * remaining, we have to do something. */

	return ret;
}

/*
 * tux3_flush_inode() for volmap or bitmap.
 *
 * If volmap or bitmap, those can clear inode dirty flags
 * immediately. Because those inodes is pinned until umount.
*/
int tux3_flush_inode_internal(struct inode *inode, unsigned delta)
{
	int err = tux3_flush_inode(inode, delta);

	/* FIXME: error handling */
	assert(atomic_read(&inode->i_count) >= 1);
	__tux3_clear_dirty_inode(inode, delta);

	return err;
}

#ifdef __KERNEL__
int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	struct sb_delta_dirty *s_ddc = tux3_sb_ddc(sb, delta);
	struct list_head *dirty_inodes = &s_ddc->dirty_inodes;
	struct inode_delta_dirty *i_ddc, *safe;
	int err;

	/* ->dirty_inodes owned by backend. No need to lock here */

	list_for_each_entry_safe(i_ddc, safe, dirty_inodes, dirty_list) {
		struct tux3_inode *tuxnode = i_ddc_to_inode(i_ddc, delta);
		struct inode *inode = &tuxnode->vfs_inode;

		assert(tuxnode->inum != TUX_BITMAP_INO &&
		       tuxnode->inum != TUX_VOLMAP_INO);

		err = tux3_flush_inode(inode, delta);
		if (err)
			goto error;
	}

	return 0;

error:
	/* FIXME: what to do for dirty_inodes on error path */
	return err;
}

/*
 * Clear inode dirty flags after flush.
 */
void tux3_clear_dirty_inodes(struct sb *sb, unsigned delta)
{
	struct sb_delta_dirty *s_ddc = tux3_sb_ddc(sb, delta);
	struct list_head *dirty_inodes = &s_ddc->dirty_inodes;
	struct inode_delta_dirty *i_ddc, *safe;

	list_for_each_entry_safe(i_ddc, safe, dirty_inodes, dirty_list) {
		struct tux3_inode *tuxnode = i_ddc_to_inode(i_ddc, delta);
		struct inode *inode = &tuxnode->vfs_inode;

		assert(tuxnode->inum != TUX_BITMAP_INO &&
		       tuxnode->inum != TUX_VOLMAP_INO);

		__tux3_clear_dirty_inode(inode, delta);
	}

	assert(list_empty(dirty_inodes)); /* someone redirtied own inode? */
}
#endif /* !__KERNEL__ */

void tux3_check_destroy_inode_flags(struct inode *inode)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	tuxnode->flags &= ~TUX3_INODE_DEAD;
	assert(tuxnode->flags == 0);
}
