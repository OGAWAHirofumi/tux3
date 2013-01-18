#ifndef ATOMIC_COMMIT_H
#define ATOMIC_COMMIT_H

#include "buffer.h"

/*
 * FIXME: this is for debug and information until complete
 * atomic-commit. Remove this after atomic-commit
 *
 * FIXME: mark_buffer_rollup() would be bad name
 */

/* mark buffer dirty if atomic-commit */
static inline void mark_buffer_dirty_atomic(struct buffer_head *buffer)
{
	tux3_mark_buffer_dirty(buffer);
}

/* mark buffer dirty if non atomic-commit */
static inline void mark_buffer_dirty_non(struct buffer_head *buffer)
{
	assert(buffer_dirty(buffer));
}

/* mark buffer dirty for rollup cycle if atomic-commit style */
static inline void mark_buffer_rollup_atomic(struct buffer_head *buffer)
{
	tux3_mark_buffer_rollup(buffer);
}

/* mark buffer dirty for rollup cycle if non atomic-commit style */
static inline void mark_buffer_rollup_non(struct buffer_head *buffer)
{
	assert(buffer_dirty(buffer));
}
#endif /* !ATOMIC_COMMIT_H */
