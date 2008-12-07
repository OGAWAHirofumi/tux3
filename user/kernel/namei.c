#include "tux3.h"

static struct dentry *tux3_lookup(struct inode *dir, struct dentry *dentry,
				 struct nameidata *nd)
{
	struct buffer_head *buffer;
	struct inode *inode = NULL;
	tux_dirent *dirent;

	dirent = tux_find_entry(dir, dentry->d_name.name, dentry->d_name.len,
				&buffer);
	if (dirent) {
		inode = tux3_iget(dir->i_sb, from_be_u32(dirent->inum));
		brelse(buffer);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	return d_splice_alias(inode, dentry);
}

static int tux_add_dirent(struct inode *dir, struct dentry *dentry,
			  struct inode *inode)
{
	loff_t where;

	where = tux_create_entry(dir, dentry->d_name.name, dentry->d_name.len,
				 tux_inode(inode)->inum, inode->i_mode);
	if (where < 0)
		return where;
	d_instantiate(dentry, inode);
	return 0;
}

static int tux3_create(struct inode *dir, struct dentry *dentry, int mode,
		       struct nameidata *nd)
{
	struct inode *inode;
	int err;

	inode = tux_create_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		err = tux_add_dirent(dir, dentry, inode);
		if (!err)
			return 0;
		inode_dec_link_count(inode);
		iput(inode);
	}
	return err;
}

static int tux3_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	return tux3_create(dir, dentry, S_IFDIR | mode, NULL);
}

static int tux3_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct inode *inode;
	int err;

	inode = tux_create_inode(dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		err = page_symlink(inode, symname, strlen(symname) + 1);
		if (!err) {
			err = tux_add_dirent(dir, dentry, inode);
			if (!err)
				return 0;
		}
		inode_dec_link_count(inode);
		iput(inode);
	}
	return err;
}

static int tux3_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct buffer_head *buffer;
	tux_dirent *entry;
	int err = -ENOENT;

	entry = tux_find_entry(dir, dentry->d_name.name, dentry->d_name.len,
			       &buffer);
	if (entry) {
		err = tux_delete_entry(buffer, entry);
		if (!err) {
			inode->i_ctime = dir->i_ctime;
			inode_dec_link_count(inode);
			err = 0;
		}
	}
	return err;
}

const struct file_operations tux_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= tux_readdir,
};

const struct inode_operations tux_dir_iops = {
	.create		= tux3_create,
	.lookup		= tux3_lookup,
//	.link		= ext3_link,
	.unlink		= tux3_unlink,
	.symlink	= tux3_symlink,
	.mkdir		= tux3_mkdir,
//	.rmdir		= ext3_rmdir,
//	.mknod		= ext3_mknod,
//	.rename		= ext3_rename,
//	.setattr	= ext3_setattr,
//	.setxattr	= generic_setxattr,
//	.getxattr	= generic_getxattr,
//	.listxattr	= ext3_listxattr,
//	.removexattr	= generic_removexattr,
//	.permission	= ext3_permission,
	/* FIXME: why doesn't ext4 support this for directory? */
//	.fallocate	= ext4_fallocate,
//	.fiemap		= ext4_fiemap,
};
