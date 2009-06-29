#ifndef ATOMIC_COMMIT_H
#define ATOMIC_COMMIT_H

/*
 * FIXME: this is for debug and information until complete
 * atomic-commit. Remove this after atomic-commit
 *
 * FIXME: mark_buffer_flush() would be bad name
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

/* mark buffer dirty for flush cycle on both style */
static inline void mark_buffer_flush(struct buffer_head *buffer)
{
#ifdef ATOMIC
	struct sb *sb = buffer_inode(buffer)->i_sb;
	if (!buffer_dirty(buffer))
		set_buffer_state_list(buffer, BUFFER_DIRTY, &sb->pinned);
#else
	mark_buffer_dirty(buffer);
#endif
}

/* mark buffer dirty for flush cycle if atomic-commit style */
static inline void mark_buffer_flush_atomic(struct buffer_head *buffer)
{
#ifdef ATOMIC
	mark_buffer_flush(buffer);
#endif
}

/* mark buffer dirty for flush cycle if non atomic-commit style */
static inline void mark_buffer_flush_non(struct buffer_head *buffer)
{
#ifdef ATOMIC
	assert(buffer_dirty(buffer));
#else
	mark_buffer_flush(buffer);
#endif
}
#endif /* !ATOMIC_COMMIT_H */
