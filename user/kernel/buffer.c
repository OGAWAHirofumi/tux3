/*
 * Buffer management
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

/* FIXME: we should rewrite with own buffer management */
void tux3_set_buffer_dirty_list(struct buffer_head *buffer, int delta,
				struct list_head *head)
{
	struct inode *inode = buffer_inode(buffer);
	struct address_space *mapping = inode->i_mapping;
	struct address_space *buffer_mapping = buffer->b_page->mapping;

	mark_buffer_dirty(buffer);

	if (!mapping->assoc_mapping)
		mapping->assoc_mapping = buffer_mapping;
	else
		BUG_ON(mapping->assoc_mapping != buffer_mapping);

	if (!buffer->b_assoc_map) {
		spin_lock(&buffer_mapping->private_lock);
		list_move_tail(&buffer->b_assoc_buffers, head);
		buffer->b_assoc_map = mapping;
		spin_unlock(&buffer_mapping->private_lock);
	}
}

/* FIXME: we should rewrite with own buffer management */
void tux3_set_buffer_dirty(struct buffer_head *buffer, int delta)
{
	struct dirty_buffers *dirty = inode_dirty_heads(buffer_inode(buffer));
	struct list_head *head = dirty_head_when(dirty, delta);
	tux3_set_buffer_dirty_list(buffer, delta, head);
}

void init_dirty_buffers(struct dirty_buffers *dirty)
{
	for (int i = 0; i < BUFFER_DIRTY_STATES; i ++)
		INIT_LIST_HEAD(&dirty->heads[i]);
}
