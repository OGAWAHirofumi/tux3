/*
 * Writeback for inodes
 */

#include "tux3.h"
#include "buffer.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: we should rewrite with own buffer management. */
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
}

/* FIXME: we should rewrite with own buffer management. */
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
