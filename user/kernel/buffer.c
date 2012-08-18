/*
 * Buffer management
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

void set_buffer_state_list(struct buffer_head *buffer, unsigned state,
			   struct list_head *list)
{
	/* FIXME: this would be broken */
	assert(state >= BUFFER_DIRTY);
	list_move_tail(&buffer->b_assoc_buffers, list);
	mark_buffer_dirty(buffer);
}

void init_dirty_buffers(struct dirty_buffers *dirty)
{
	for (int i = 0; i < BUFFER_DIRTY_STATES; i ++)
		INIT_LIST_HEAD(&dirty->heads[i]);
}
