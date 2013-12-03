/*
 * Inode deletion mark.
 *
 * On tux3, frontend doesn't delete inode synchronously. Instead,
 * frontend just mark inode dirty to delete. And backend works for
 * deleting inode.
 *
 * It makes backend simpler and race free, and frontend doesn't need
 * to wait I/O to delete inode.
 *
 * To do it, this provides the deletion mark infrastructure.
 */

#include "tux3_fork.h"

TUX3_DEFINE_STATE_FNS(unsigned, dead, DEAD_DIRTY,
		      IFLAGS_DEAD_BITS, IFLAGS_DEAD_SHIFT);

static int tux3_inode_is_dead(struct tux3_inode *tuxnode)
{
	return tux3_deadsta_has_delta(tuxnode->flags) ||
		(tuxnode->flags & TUX3_INODE_DEAD);
}

/*
 * Mark inode dirty to delete. (called from ->drop_inode()).
 * Caller must hold inode->i_lock.
 */
static void __tux3_mark_inode_to_delete(struct inode *inode, unsigned delta)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned flags;

	trace("mark as dead: inum %Lu, delta %d", tuxnode->inum, delta);

	spin_lock(&tuxnode->lock);
	flags = tuxnode->flags;
	assert(!tux3_deadsta_has_delta(flags));
	/* Mark inode dirty to delete on this delta */
	tuxnode->flags |= tux3_deadsta_delta(delta);
	spin_unlock(&tuxnode->lock);

	/*
	 * Tell dead inode to backend by marking as dirty.
	 *
	 * Hack: this is called under inode->i_lock. So, we call
	 * internal ->dirty_inode(), and change inode->i_flags here
	 * directly.
	 */
	tux3_dirty_inode(inode, I_DIRTY_SYNC);
	inode->i_state |= I_DIRTY_SYNC;
	/* FIXME: we should wake up flusher if inode was clean */
}

void tux3_mark_inode_to_delete(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned delta;

	/* inode has dead mark already */
	if (tux3_inode_is_dead(tuxnode))
		return;

	change_begin_atomic(sb);

	delta = tux3_inode_delta(inode);
	__tux3_mark_inode_to_delete(inode, delta);

	change_end_atomic(sb);
}

/*
 * Check whether inode was dead. Then clear iattr dirty to tell no
 * need to iattrfork anymore if needed.
 */
static void tux3_dead_read_and_clear(struct inode *inode,
				     unsigned *deleted,
				     unsigned delta)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned flags = tuxnode->flags;

	*deleted = 0;

	if (tux3_deadsta_has_delta(flags) &&
	    tux3_deadsta_get_delta(flags) == tux3_delta(delta)) {
		*deleted = 1;
		flags |= TUX3_INODE_DEAD;
		tuxnode->flags = tux3_deadsta_clear(flags);
	}
}
