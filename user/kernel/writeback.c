/*
 * Writeback for inodes
 */

#include "tux3.h"
#include "buffer.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: probably, we should rewrite with own buffer management. */

/* This is hook of __mark_inode_dirty() */
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

void tux3_mark_buffer_dirty(struct buffer_head *buffer)
{
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
	tux3_dirty_inode(buffer_inode(buffer), I_DIRTY_PAGES);
}

void tux3_mark_buffer_rollup(struct buffer_head *buffer)
{
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);

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

	tux3_set_buffer_dirty_list(buffer, sb->rollup,
				   dirty_head_when(&sb->pinned, sb->rollup));
}

int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	return 0;
}

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	return 0;
}
