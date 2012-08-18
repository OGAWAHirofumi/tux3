#ifndef LIBKLIB_FS_H
#define LIBKLIB_FS_H

/* depending on tux3 */

struct nameidata {
};

/*
 * dentry stuff
 */

struct qstr {
	/* unsigned int hash; */
	unsigned int len;
	const unsigned char *name;
};

struct dentry {
	struct qstr d_name;
	struct inode *d_inode;
};

void d_instantiate(struct dentry *dentry, struct inode *inode);
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry);

/*
 * fs stuff
 */

enum rw { READ, WRITE };

/*
 * File types
 *
 * NOTE! These match bits 12..15 of stat.st_mode
 * (ie "(i_mode >> 12) & 15").
 */
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

typedef int (*filldir_t)(void *, const char *, int, loff_t, u64, unsigned);

void inc_nlink(struct inode *inode);
void drop_nlink(struct inode *inode);
void clear_nlink(struct inode *inode);
void set_nlink(struct inode *inode, unsigned int nlink);

void mark_inode_dirty(struct inode *inode);
static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}

#endif /* !LIBKLIB_FS_H */
