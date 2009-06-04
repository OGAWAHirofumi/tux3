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

/* dummy for not including inode.c */
int __weak write_inode(struct inode *inode)
{
	assert(0);
	return 0;
}

int sync_inode(struct inode *inode)
{
	int err = flush_buffers(mapping(inode));
	if (!err)
		err = write_inode(inode);
	return err;
}

/* dummy for not including super.c */
int __weak save_sb(struct sb *sb)
{
	assert(0);
	return 0;
}

int sync_super(struct sb *sb)
{
	int err;

	printf("sync rootdir\n");
	if ((err = sync_inode(sb->rootdir)))
		return err;
	printf("sync atom table\n");
	if ((err = sync_inode(sb->atable)))
		return err;
	printf("sync bitmap\n");
	if ((err = sync_inode(sb->bitmap)))
		return err;
	printf("sync volmap\n");
	if ((err = flush_buffers(sb->volmap->map)))
		return err;
	printf("sync super\n");
	if ((err = save_sb(sb)))
		return err;

	return 0;
}
