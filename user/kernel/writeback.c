/*
 * Writeback for inodes
 *
 * lock order:
 *     inode->i_lock
 *         tuxnode->lock
 *         sb->dirty_inodes_lock
 */

#include "tux3.h"
#include "buffer.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: probably, we should rewrite with own buffer management. */

#if I_DIRTY != ((1 << 0) | (1 << 1) | (1 << 2))
#error "I_DIRTY was changed"
#endif

/* I_DIRTY_SYNC, I_DIRTY_DATASYNC, and I_DIRTY_PAGES */
#define NUM_DIRTY_BITS		3

static inline unsigned tux3_delta(unsigned delta)
{
	return delta & (BUFFER_DIRTY_STATES - 1);
}

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
	unsigned flags;
	flags = (tux_inode(inode)->flags >> tux3_dirty_shift(delta)) & I_DIRTY;
	return flags;
}

/* Choice sb->delta or sb->rollup from inode */
static inline int tux3_inode_delta(struct inode *inode)
{
	unsigned delta;

	switch (tux_inode(inode)->inum) {
	case TUX_VOLMAP_INO:
		/* volmap are special buffer, and always DEFAULT_DIRTY_WHEN */
		delta = DEFAULT_DIRTY_WHEN;
		break;
	case TUX_BITMAP_INO:
		delta = tux_sb(inode->i_sb)->rollup;
		break;
	default:
		delta = tux_sb(inode->i_sb)->delta;
		break;
	}

	return delta;
}

/* This is hook of __mark_inode_dirty() and called I_DIRTY_PAGES too */
void tux3_dirty_inode(struct inode *inode, int flags)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned mask = tux3_dirty_mask(flags, tux3_inode_delta(inode));

	if ((tuxnode->flags & mask) == mask)
		return;

	spin_lock(&tuxnode->lock);
	if ((tuxnode->flags & mask) != mask) {
		tuxnode->flags |= mask;

		spin_lock(&sb->dirty_inodes_lock);
		if (list_empty(&tuxnode->dirty_list))
			list_add_tail(&tuxnode->dirty_list, &sb->dirty_inodes);
		spin_unlock(&sb->dirty_inodes_lock);
	}
	spin_unlock(&tuxnode->lock);
}

/* Clear dirty flags for delta (caller must hold inode->i_lock/tuxnode->lock) */
static void tux3_clear_dirty_inode_nolock(struct inode *inode, unsigned delta)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	unsigned mask = tux3_dirty_mask(I_DIRTY, delta);

	/* Clear dirty flags for delta */
	tuxnode->flags &= ~mask;

	/* Remove inode from list */
	if (!tuxnode->flags) {
		spin_lock(&sb->dirty_inodes_lock);
		list_del_init(&tuxnode->dirty_list);
		spin_unlock(&sb->dirty_inodes_lock);
	}

	/* Update inode state */
	if (tuxnode->flags)
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
	tux3_clear_dirty_inode_nolock(inode, delta);
	spin_unlock(&tuxnode->lock);
	spin_unlock(&inode->i_lock);
}

/* Clear dirty flags for frontend delta */
void tux3_clear_dirty_inode(struct inode *inode)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	spin_lock(&inode->i_lock);
	spin_lock(&tuxnode->lock);
	tux3_clear_dirty_inode_nolock(inode, tux3_inode_delta(inode));
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

static int volmap_buffer(struct buffer_head *buffer)
{
	struct inode *inode = buffer_inode(buffer);
	return inode == tux_sb(inode->i_sb)->volmap;
}

/* Mark buffer as dirty to flush at delta flush */
void tux3_mark_buffer_dirty(struct buffer_head *buffer)
{
	assert(volmap_buffer(buffer));

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

	tux3_set_buffer_dirty(buffer, DEFAULT_DIRTY_WHEN);
	/* FIXME: we need to dirty inode only if buffer became
	 * dirty. However, tux3_set_buffer_dirty doesn't provide it */
	__tux3_mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);
}

/* Mark buffer as dirty to flush at rollup flush */
void tux3_mark_buffer_rollup(struct buffer_head *buffer)
{
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);

	assert(volmap_buffer(buffer));

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

	tux3_set_buffer_dirty_list(buffer, sb->rollup, &sb->rollup_buffers);
}

static inline int tux3_flush_buffers(struct inode *inode, unsigned delta)
{
	return flush_list(dirty_head_when(inode_dirty_heads(inode), delta));
}

#ifdef __KERNEL__
int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	/* FIXME: linux writeback doesn't allow to control writeback
	 * timing. */
	unsigned dirty;
	int err;

	list_del_init(&tux_inode(inode)->dirty_list);
	trace("inum %Lu", tux_inode(inode)->inum);

	err = tux3_flush_buffers(inode, delta);
	if (err)
		goto out;

	/* Get flags after tux3_flush_buffers() to check TUX3_DIRTY_BTREE */
	dirty = tux3_dirty_flags(inode, delta);

	if (dirty & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		err = tux3_write_inode(inode, NULL);
		if (err)
			goto out;
	}

	/*
	 * We can clear dirty flags after flush. We have per-delta
	 * flags, or volmap is not re-dirtied while flushing.
	 */
	__tux3_clear_dirty_inode(inode, delta);
out:
	/* FIXME: In the error path, dirty state is still remaining,
	 * we have to do something. */

	return err;
}

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	struct tux3_inode *tuxnode, *safe;
	LIST_HEAD(dirty_inodes);
	int err;

	/* FIXME: we would want to use per-delta dirty_inodes lists,
	 * to separate dirty inodes for the delta */
	spin_lock(&sb->dirty_inodes_lock);
	list_splice_init(&sb->dirty_inodes, &dirty_inodes);
	spin_unlock(&sb->dirty_inodes_lock);

	list_for_each_entry_safe(tuxnode, safe, &dirty_inodes, dirty_list) {
		struct inode *inode = &tuxnode->vfs_inode;
		/*
		 * FIXME: this is hack. those inodes can be dirtied by
		 * tux3_flush_inode() of other inodes, so it should be
		 * flushed after other inodes.
		 */
		switch (tuxnode->inum) {
		case TUX_BITMAP_INO:
		case TUX_VOLMAP_INO:
			continue;
		}

		err = tux3_flush_inode(inode, delta);
		if (err)
			goto error;
	}
	/* The bitmap and volmap inode is handled in the delta */
	spin_lock(&sb->dirty_inodes_lock);
	tuxnode = tux_inode(sb->bitmap);
	if (!list_empty(&tuxnode->dirty_list))
		list_move(&tuxnode->dirty_list, &sb->dirty_inodes);
	tuxnode = tux_inode(sb->volmap);
	if (!list_empty(&tuxnode->dirty_list))
		list_move(&tuxnode->dirty_list, &sb->dirty_inodes);
	spin_unlock(&sb->dirty_inodes_lock);

	assert(list_empty(&dirty_inodes)); /* someone redirtied own inode? */

	return 0;

error:
	spin_lock(&sb->dirty_inodes_lock);
	list_splice_init(&dirty_inodes, &sb->dirty_inodes);
	spin_unlock(&sb->dirty_inodes_lock);

	return err;
}
#endif /* !__KERNEL__ */
