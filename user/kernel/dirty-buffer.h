#ifndef ATOMIC_COMMIT_H
#define ATOMIC_COMMIT_H

/*
 * FIXME: this is for debug and information until complete
 * atomic-commit. Remove this after atomic-commit
 *
 * FIXME: mark_buffer_rollup() would be bad name
 */

/* mark buffer dirty if atomic-commit */
static inline void mark_buffer_dirty_atomic(struct buffer_head *buffer)
{
#ifdef ATOMIC
	mark_buffer_dirty(buffer);
#endif
}

/* mark buffer dirty if non atomic-commit */
static inline void mark_buffer_dirty_non(struct buffer_head *buffer)
{
#ifdef ATOMIC
	assert(buffer_dirty(buffer));
#else
	mark_buffer_dirty(buffer);
#endif
}

/* mark buffer dirty for rollup cycle on both style */
static inline void mark_buffer_rollup(struct buffer_head *buffer)
{
#ifdef ATOMIC
	struct sb *sb = buffer_inode(buffer)->i_sb;
	if (!buffer_dirty(buffer)) {
		unsigned rollup = sb->rollup;
		set_buffer_state_list(buffer, BUFFER_DIRTY + delta_when(rollup),
				      dirty_head_when(&sb->pinned, rollup));
	}
#else
	mark_buffer_dirty(buffer);
#endif
}

/* mark buffer dirty for rollup cycle if atomic-commit style */
static inline void mark_buffer_rollup_atomic(struct buffer_head *buffer)
{
#ifdef ATOMIC
	mark_buffer_rollup(buffer);
#endif
}

/* mark buffer dirty for rollup cycle if non atomic-commit style */
static inline void mark_buffer_rollup_non(struct buffer_head *buffer)
{
#ifdef ATOMIC
	assert(buffer_dirty(buffer));
#else
	mark_buffer_rollup(buffer);
#endif
}
#endif /* !ATOMIC_COMMIT_H */
