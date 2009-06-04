#ifndef TUX3_WRITEBACK_H
#define TUX3_WRITEBACK_H

void mark_inode_dirty(struct inode *inode);
void mark_buffer_dirty(struct buffer_head *buffer);

#endif /* !TUX3_WRITEBACK_H */
