#ifndef TUX3_WRITEBACK_H
#define TUX3_WRITEBACK_H

#define I_DIRTY_SYNC		(1 << 0)
#define I_DIRTY_DATASYNC	(1 << 1)
#define I_DIRTY_PAGES		(1 << 2)
#define I_FREEING		(1 << 5)
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)

struct sb;
struct inode;

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta);
void clear_inode(struct inode *inode);
void __mark_inode_dirty(struct inode *inode, unsigned flags);
void mark_inode_dirty(struct inode *inode);
void mark_inode_dirty_sync(struct inode *inode);
void mark_buffer_dirty(struct buffer_head *buffer);
int sync_inode(struct inode *inode);
int sync_inodes(struct sb *sb);
int sync_super(struct sb *sb);

#endif /* !TUX3_WRITEBACK_H */
