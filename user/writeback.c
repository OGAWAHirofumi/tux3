#include "tux3.h"

void mark_inode_dirty(struct inode *inode)
{
	if (list_empty(&inode->list))
		list_add_tail(&inode->list, &inode->i_sb->dirty_inodes);
}

void mark_buffer_dirty(struct buffer_head *buffer)
{
	if (!buffer_dirty(buffer)) {
		set_buffer_dirty(buffer);
		mark_inode_dirty(buffer_inode(buffer));
	}
}
