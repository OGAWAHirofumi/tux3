#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

void clear_inode(struct inode *inode)
{
	list_del_init(&inode->list);
	inode->i_state &= ~I_DIRTY;
}

void __mark_inode_dirty(struct inode *inode, unsigned flags)
{
	if ((inode->i_state & flags) != flags) {
		inode->i_state |= flags;
		if (list_empty(&inode->list))
			list_add_tail(&inode->list, &inode->i_sb->dirty_inodes);
	}
}

void mark_inode_dirty(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY);
}

void mark_inode_dirty_sync(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

/* Mark buffer as dirty to flush at delta flush */
void tux3_mark_buffer_dirty(struct buffer_head *buffer)
{
	if (!buffer_dirty(buffer)) {
		set_buffer_dirty(buffer);
		__mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);
	}
}

/* Mark buffer as dirty to flush at rollup flush */
void tux3_mark_buffer_rollup(struct buffer_head *buffer)
{
	if (!buffer_dirty(buffer)) {
		struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
		unsigned rollup = sb->rollup;
		set_buffer_state_list(buffer, BUFFER_DIRTY + delta_when(rollup),
				      dirty_head_when(&sb->pinned, rollup));
	}
}

int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	unsigned dirty = inode->i_state;
	int err;

	/*
	 * iput() doesn't free inode if I_DIRTY. Grab refcount to tell
	 * inode state was changed to iput().
	 */
	__iget(inode);

	if (inode->i_state & I_DIRTY_PAGES) {
		/* To handle redirty, this clears before flushing */
		inode->i_state &= ~I_DIRTY_PAGES;
		err = flush_buffers_when(mapping(inode), delta);
		if (err)
			goto error;
	}
	if (inode->i_state & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		/* To handle redirty, this clears before flushing */
		inode->i_state &= ~(I_DIRTY_SYNC | I_DIRTY_DATASYNC);
		err = write_inode(inode);
		if (err)
			goto error;
	}
	if (!(inode->i_state & I_DIRTY))
		list_del_init(&inode->list);

	iput(inode);

	return 0;

error:
	inode->i_state = dirty;
	return err;
}

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	struct inode *inode, *safe;
	LIST_HEAD(dirty_inodes);
	int err;

	list_splice_init(&sb->dirty_inodes, &dirty_inodes);

	list_for_each_entry_safe(inode, safe, &dirty_inodes, list) {
		/*
		 * FIXME: this is hack. those inodes can be dirtied by
		 * tux3_flush_inode() of other inodes, so it should be
		 * flushed after other inodes.
		 */
		switch (inode->inum) {
		case TUX_BITMAP_INO:
		case TUX_VOLMAP_INO:
			continue;
		}

		err = tux3_flush_inode(inode, delta);
		if (err)
			goto error;
	}
#ifdef ATOMIC
	/* If atomic-commit, bitmap and volmap is handled in the delta */
	if (!list_empty(&sb->bitmap->list))
		list_move(&sb->bitmap->list, &sb->dirty_inodes);
	if (!list_empty(&sb->volmap->list))
		list_move(&sb->volmap->list, &sb->dirty_inodes);
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
	assert(list_empty(&dirty_inodes)); /* someone redirtied own inode? */

	return 0;

error:
	list_splice_init(&dirty_inodes, &sb->dirty_inodes);
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
