#ifndef TUX3_WRITEBACK_H
#define TUX3_WRITEBACK_H

struct sb;
struct inode;

void clear_inode(struct inode *inode);
void mark_inode_dirty(struct inode *inode);
void mark_buffer_dirty(struct buffer_head *buffer);
int sync_inode(struct inode *inode);
int sync_super(struct sb *sb);

#endif /* !TUX3_WRITEBACK_H */
