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

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	struct sb_delta_dirty *s_ddc = tux3_sb_ddc(sb, delta);
	struct list_head *dirty_inodes = &s_ddc->dirty_inodes;
	struct inode_delta_dirty *i_ddc, *safe;
	int err;

	list_for_each_entry_safe(i_ddc, safe, dirty_inodes, dirty_list) {
		struct tux3_inode *tuxnode = i_ddc_to_inode(i_ddc, delta);
		struct inode *inode = &tuxnode->vfs_inode;

		assert(tuxnode->inum != TUX_BITMAP_INO &&
		       tuxnode->inum != TUX_VOLMAP_INO);

		err = tux3_flush_inode(inode, delta);
		if (err)
			goto error;
	}
#ifndef ATOMIC
	err = unstash(sb, &sb->defree, apply_defered_bfree);
	if (err)
		goto error;
	err = tux3_flush_inode_internal(sb->bitmap, TUX3_INIT_DELTA);
	if (err)
		goto error;
	err = tux3_flush_inode_internal(sb->volmap, TUX3_INIT_DELTA);
	if (err)
		goto error;
#endif

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
	if ((err = tux3_flush_inodes(sb, TUX3_INIT_DELTA)))
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
