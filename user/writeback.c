#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

#include "kernel/writeback.c"

void clear_inode(struct inode *inode)
{
	inode->i_state = I_FREEING;
}

void __mark_inode_dirty(struct inode *inode, unsigned flags)
{
	if (flags & (I_DIRTY_SYNC | I_DIRTY_DATASYNC))
		tux3_dirty_inode(inode, flags);

	if ((inode->i_state & flags) != flags)
		inode->i_state |= flags;
}

void mark_inode_dirty(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY);
}

void mark_inode_dirty_sync(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	unsigned dirty;
	int err;

	/*
	 * iput() doesn't free inode if I_DIRTY. Grab refcount to tell
	 * inode state was changed to iput().
	 */
	__iget(inode);

	list_del_init(&tux_inode(inode)->dirty_list);

	err = tux3_flush_buffers(inode, delta);
	if (err)
		goto out;

	/* Get flags after tux3_flush_buffers() to check TUX3_DIRTY_BTREE */
	dirty = tux3_dirty_flags(inode, delta);

	if (dirty & (TUX3_DIRTY_BTREE | I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		err = write_inode(inode);
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
	iput(inode);

	return err;
}

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	struct sb_delta_dirty *s_ddc = tux3_sb_ddc(sb, delta);
	struct list_head *dirty_inodes = &s_ddc->dirty_inodes;
	struct tux3_inode *tuxnode, *safe;
	int err;

	list_for_each_entry_safe(tuxnode, safe, dirty_inodes, dirty_list) {
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
#ifdef ATOMIC
	/* The bitmap and volmap inode is handled in do_commit. Just remove. */
	tuxnode = tux_inode(sb->bitmap);
	if (!list_empty(&tuxnode->dirty_list))
		list_del_init(&tuxnode->dirty_list);
	tuxnode = tux_inode(sb->volmap);
	if (!list_empty(&tuxnode->dirty_list))
		list_del_init(&tuxnode->dirty_list);
#else
	err = unstash(sb, &sb->defree, apply_defered_bfree);
	if (err)
		goto error;
	err = tux3_flush_inode(sb->bitmap, DEFAULT_DIRTY_WHEN);
	if (err)
		goto error;
	err = tux3_flush_inode(sb->volmap, DEFAULT_DIRTY_WHEN);
	if (err)
		goto error;
#endif
	assert(list_empty(dirty_inodes)); /* someone redirtied own inode? */

	return 0;

error:
	/* FIXME: what to do for dirty_inodes on error path */
	return err;
}

int sync_super(struct sb *sb)
{
#ifdef ATOMIC
	return force_delta(sb);
#else
	int err;

	trace("sync inodes");
	if ((err = tux3_flush_inodes(sb, DEFAULT_DIRTY_WHEN)))
		return err;
	trace("sync super");
	if ((err = save_sb(sb)))
		return err;

	return 0;
#endif /* !ATOMIC */
}

#ifndef ATOMIC
int force_rollup(struct sb *sb)
{
	return sync_super(sb);
}

int force_delta(struct sb *sb)
{
	return sync_super(sb);
}
#endif
