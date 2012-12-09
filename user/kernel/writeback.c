/*
 * Writeback for inodes
 */

#include "tux3.h"
#include "buffer.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: probably, we should rewrite with own buffer management. */

/* This is hook of __mark_inode_dirty() and called I_DIRTY_PAGES too */
void tux3_dirty_inode(struct inode *inode, int flags)
{
	struct sb *sb = tux_sb(inode->i_sb);

	/* FIXME: we should save flags. And use it to know whether we
	 * have to write inode data or not */
	spin_lock(&sb->dirty_inodes_lock);
	if (list_empty(&tux_inode(inode)->dirty_list))
		list_add_tail(&tux_inode(inode)->dirty_list, &sb->dirty_inodes);
	spin_unlock(&sb->dirty_inodes_lock);
}

void tux3_clear_dirty_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	/* FIXME: if we saved flags, we should clear it here. */
	spin_lock(&sb->dirty_inodes_lock);
	list_del_init(&tux_inode(inode)->dirty_list);
	spin_unlock(&sb->dirty_inodes_lock);
#ifndef __KERNEL__
	inode->i_state &= ~I_DIRTY;
#endif
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
	 * timing. And it clears inode dirty state with own timing, so
	 * we would want to know those somehow.
	 *
	 * For now, we are using this dummy state. */
	unsigned long state = I_DIRTY;
	int err;

	/* FIXME: see above comment. sb->volmap metadata should never
	 * be marked as dirty actually */
	if (tux_inode(inode)->inum == TUX_VOLMAP_INO)
		state = I_DIRTY_PAGES;

	list_del_init(&tux_inode(inode)->dirty_list);
	trace("inum %Lu", tux_inode(inode)->inum);

	if (state & I_DIRTY_PAGES) {
		/* To handle redirty, this clears before flushing */
		state &= ~I_DIRTY_PAGES;
		err = tux3_flush_buffers(inode, delta);
		if (err)
			goto error;
	}
	if (state & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		/* To handle redirty, this clears before flushing */
		state &= ~(I_DIRTY_SYNC | I_DIRTY_DATASYNC);
		err = tux3_write_inode(inode, NULL);
		if (err)
			goto error;
	}

	return 0;

error:
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
