#ifndef TUX3_WRITEBACK_H
#define TUX3_WRITEBACK_H

#define I_DIRTY_SYNC		(1 << 0)
#define I_DIRTY_DATASYNC	(1 << 1)
#define I_DIRTY_PAGES		(1 << 2)
#define __I_NEW			3
#define I_NEW			(1 << __I_NEW)
#define I_FREEING		(1 << 5)
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define I_BAD			(1 << 31)

struct sb;
struct inode;

void clear_inode(struct inode *inode);
void __mark_inode_dirty(struct inode *inode, unsigned flags);
void mark_inode_dirty(struct inode *inode);
void mark_inode_dirty_sync(struct inode *inode);
int sync_super(struct sb *sb);

#endif /* !TUX3_WRITEBACK_H */
