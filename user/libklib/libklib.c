#include <tux3user.h>

void inc_nlink(struct inode *inode)
{
	inode->i_nlink++;
}

void drop_nlink(struct inode *inode)
{
	assert(inode->i_nlink > 0);
	inode->i_nlink--;
}

void clear_nlink(struct inode *inode)
{
	inode->i_nlink = 0;
}

void set_nlink(struct inode *inode, unsigned int nlink)
{
	if (!nlink)
		clear_nlink(inode);
	else
		inode->i_nlink = nlink;
}

void d_instantiate(struct dentry *dentry, struct inode *inode)
{
	dentry->d_inode = inode;
}

struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	d_instantiate(dentry, inode);
	return NULL;
}

void truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	inode->i_size = newsize;
	if (newsize < oldsize)
		truncate_inode_pages(mapping(inode), newsize);
}
