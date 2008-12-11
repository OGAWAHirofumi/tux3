#include "tux3.h"

static struct dentry *tux3_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct buffer_head *buffer;
	struct inode *inode;
	tux_dirent *entry;

	entry = tux_find_entry(dir, dentry->d_name.name, dentry->d_name.len, &buffer);
	if (IS_ERR(entry)) {
		if (PTR_ERR(entry) != -ENOENT)
			return ERR_CAST(entry);
		inode = NULL;
		goto out;
	}
	inode = tux3_iget(dir->i_sb, from_be_u32(entry->inum));
	brelse(buffer);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
out:
	return d_splice_alias(inode, dentry);
}

static int tux_add_dirent(struct inode *dir, struct dentry *dentry, struct inode *inode)
{
	loff_t where;

	where = tux_create_entry(dir, dentry->d_name.name, dentry->d_name.len,
				 tux_inode(inode)->inum, inode->i_mode);
	if (where < 0)
		return where;
	d_instantiate(dentry, inode);
	return 0;
}

static int tux_del_dirent(struct inode *dir, struct dentry *dentry)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_entry(dir, dentry->d_name.name, dentry->d_name.len, &buffer);
	return IS_ERR(entry) ? PTR_ERR(entry) : tux_delete_entry(buffer, entry);
}

static int tux3_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
	struct inode *inode;
	int err;

	inode = tux_create_inode(dir, mode, 0);
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
	int err;
	if (dir->i_nlink >= TUX_LINK_MAX)
		return -EMLINK;
	err = tux3_create(dir, dentry, S_IFDIR | mode, NULL);
	if (!err)
		inode_inc_link_count(dir);
	return err;
}

static int tux3_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int err;

	if (inode->i_nlink >= TUX_LINK_MAX)
		return -EMLINK;

	inode->i_ctime = gettime();
	inode_inc_link_count(inode);
	atomic_inc(&inode->i_count);
	err = tux_add_dirent(dir, dentry, inode);
	if (err) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	return err;
}

static int tux3_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct inode *inode;
	int err;

	inode = tux_create_inode(dir, S_IFLNK | S_IRWXUGO, 0);
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
	int err = tux_del_dirent(dir, dentry);

	if (!err) {
		inode->i_ctime = dir->i_ctime;
		inode_dec_link_count(inode);
	}
	return err;
}

static int tux3_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct buffer_head *old_buffer, *new_buffer;
	tux_dirent *old_de, *new_de = NULL;

	old_de = tux_find_entry(old_dir, old_dentry->d_name.name,
		old_dentry->d_name.len, &old_buffer);
	if (IS_ERR(old_de))
		return PTR_ERR(old_de);

	if (new_inode) {
		int err = -ENOTEMPTY;
		if (!tux_dir_is_empty(new_inode))
			return err;

		new_de = tux_find_entry(new_dir, new_dentry->d_name.name,
			new_dentry->d_name.len, &new_buffer);
		if (IS_ERR(new_de))
			return PTR_ERR(old_de);

		if ((err = tux_delete_entry(new_buffer, new_de)))
			return err;

		new_inode->i_ctime = new_dentry->d_parent->d_inode->i_ctime;
		inode_dec_link_count(new_inode);
		err = tux_create_entry(new_dentry->d_parent->d_inode,
				       new_dentry->d_name.name,
				       new_dentry->d_name.len,
				       tux_inode(old_inode)->inum,
				       old_inode->i_mode);

		if (err)
			return err;

	} else {
		int err = tux_add_dirent(new_dentry->d_parent->d_inode, new_dentry, old_inode);
		if (err)
			return err;
	}
	old_inode->i_ctime = gettime();
	tux_delete_entry(old_buffer, old_de);
	return 0;
}

static int tux3_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err = -ENOTEMPTY;

	if (tux_dir_is_empty(inode)) {

		err = tux_del_dirent(dir, dentry);

		if (!err) {
			inode->i_ctime = dir->i_ctime;
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
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
	.link		= tux3_link,
	.unlink		= tux3_unlink,
	.symlink	= tux3_symlink,
	.mkdir		= tux3_mkdir,
	.rmdir		= tux3_rmdir,
//	.mknod		= ext3_mknod,
	.rename		= tux3_rename,
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
