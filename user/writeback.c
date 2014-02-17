#include "tux3user.h"

#ifndef trace
#define trace trace_off
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

int sync_super(struct sb *sb)
{
	return force_delta(sb);
}
