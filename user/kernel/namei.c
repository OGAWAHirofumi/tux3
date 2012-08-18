/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include "tux3.h"

static struct dentry *tux3_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct buffer_head *buffer;
	struct inode *inode;
	tux_dirent *entry;

	entry = tux_find_dirent(dir, dentry->d_name.name, dentry->d_name.len, &buffer);
	if (IS_ERR(entry)) {
		if (PTR_ERR(entry) != -ENOENT)
			return ERR_PTR(PTR_ERR(entry));
		inode = NULL;
		goto out;
	}
	inode = tux3_iget(dir->i_sb, from_be_u64(entry->inum));
	brelse(buffer);
	if (IS_ERR(inode))
		return ERR_PTR(PTR_ERR(inode));
out:
	return d_splice_alias(inode, dentry);
}

static int __tux_add_dirent(struct inode *dir, struct dentry *dentry, struct inode *inode)
{
	return tux_create_dirent(dir, dentry->d_name.name, dentry->d_name.len,
				 tux_inode(inode)->inum, inode->i_mode);
}

static int tux_add_dirent(struct inode *dir, struct dentry *dentry, struct inode *inode)
{
	int err = __tux_add_dirent(dir, dentry, inode);
	if (!err)
		d_instantiate(dentry, inode);
	return err;
}

static int tux_del_dirent(struct inode *dir, struct dentry *dentry)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_dirent(dir, dentry->d_name.name, dentry->d_name.len, &buffer);

	return IS_ERR(entry) ? PTR_ERR(entry) : tux_delete_dirent(buffer, entry);
}

static int tux3_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		      dev_t rdev)
{
	struct inode *inode;
	int err;

	if (!huge_valid_dev(rdev))
		return -EINVAL;

	change_begin(tux_sb(dir->i_sb));
	inode = tux_create_inode(dir, mode, rdev);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		err = tux_add_dirent(dir, dentry, inode);
		if (!err) {
			if ((inode->i_mode & S_IFMT) == S_IFDIR)
				inode_inc_link_count(dir);
			goto out;
		}
		clear_nlink(inode);
		mark_inode_dirty(inode);
		iput(inode);
	}
out:
	change_end(tux_sb(dir->i_sb));
	return err;
}

static int tux3_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       struct nameidata *nd)
{
	return tux3_mknod(dir, dentry, mode, 0);
}

static int tux3_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (dir->i_nlink >= TUX_LINK_MAX)
		return -EMLINK;
	return tux3_mknod(dir, dentry, S_IFDIR | mode, 0);
}

static int tux3_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int err;

	if (inode->i_nlink >= TUX_LINK_MAX)
		return -EMLINK;

	change_begin(tux_sb(inode->i_sb));
	inode->i_ctime = gettime();
	inode_inc_link_count(inode);
	atomic_inc(&inode->i_count);
	err = tux_add_dirent(dir, dentry, inode);
	if (err) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	change_end(tux_sb(inode->i_sb));
	return err;
}

static int tux3_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct inode *inode;
	int err;

	change_begin(tux_sb(dir->i_sb));
	inode = tux_create_inode(dir, S_IFLNK | S_IRWXUGO, 0);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		err = page_symlink(inode, symname, strlen(symname) + 1);
		if (!err) {
			err = tux_add_dirent(dir, dentry, inode);
			if (!err)
				goto out;
		}
		inode_dec_link_count(inode);
		iput(inode);
	}
out:
	change_end(tux_sb(dir->i_sb));
	return err;
}

static int tux3_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	change_begin(tux_sb(inode->i_sb));
	int err = tux_del_dirent(dir, dentry);
	if (!err) {
		inode->i_ctime = dir->i_ctime;
		inode_dec_link_count(inode);
	}
	change_end(tux_sb(inode->i_sb));
	return err;
}

static int tux3_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err = tux_dir_is_empty(inode);

	if (!err) {
		change_begin(tux_sb(inode->i_sb));
		err = tux_del_dirent(dir, dentry);
		if (!err) {
			inode->i_ctime = dir->i_ctime;
			inode->i_size = 0;
			clear_nlink(inode);
			mark_inode_dirty(inode);
			inode_dec_link_count(dir);
		}
		change_end(tux_sb(inode->i_sb));
	}
	return err;
}

static int tux3_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct buffer_head *old_buffer, *new_buffer;
	tux_dirent *old_entry, *new_entry;
	int err, new_subdir = 0;

	old_entry = tux_find_dirent(old_dir, old_dentry->d_name.name,
				    old_dentry->d_name.len, &old_buffer);
	if (IS_ERR(old_entry))
		return PTR_ERR(old_entry);

	/* FIXME: is this needed? */
	BUG_ON(from_be_u64(old_entry->inum) != tux_inode(old_inode)->inum);

	change_begin(tux_sb(old_inode->i_sb));
	if (new_inode) {
		int old_is_dir = S_ISDIR(old_inode->i_mode);
		if (old_is_dir) {
			err = tux_dir_is_empty(new_inode);
			if (err)
				goto error;
		}

		new_entry = tux_find_dirent(new_dir, new_dentry->d_name.name,
					new_dentry->d_name.len, &new_buffer);
		if (IS_ERR(new_entry)) {
			BUG_ON(PTR_ERR(new_entry) == -ENOENT);
			err = PTR_ERR(new_entry);
			goto error;
		}
		/* this releases new_buffer */
		tux_update_dirent(new_buffer, new_entry, old_inode);
		new_inode->i_ctime = new_dir->i_ctime;
		if (old_is_dir)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		new_subdir = S_ISDIR(old_inode->i_mode) && new_dir != old_dir;
		if (new_subdir) {
			if (new_dir->i_nlink >= TUX_LINK_MAX) {
				err = -EMLINK;
				goto error;
			}
		}
		err = __tux_add_dirent(new_dir, new_dentry, old_inode);
		if (err)
			goto error;
		if (new_subdir)
			inode_inc_link_count(new_dir);
	}
	old_inode->i_ctime = new_dir->i_ctime;
	mark_inode_dirty(old_inode);

	err = tux_delete_dirent(old_buffer, old_entry);
	if (err) {
		printk(KERN_ERR "TUX3: %s: couldn't delete old entry (%Lu)\n",
		       __func__, (L)tux_inode(old_inode)->inum);
		/* FIXME: now, we have hardlink even if it's dir. */
		inode_inc_link_count(old_inode);
	}
	if (!err && new_subdir)
		inode_dec_link_count(old_dir);

	change_end(tux_sb(old_inode->i_sb));
	return err;

error:
	change_end(tux_sb(old_inode->i_sb));
	brelse(old_buffer);
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
	.mknod		= tux3_mknod,
	.rename		= tux3_rename,
//	.setattr	= ext3_setattr,
	.getattr	= tux3_getattr
//	.setxattr	= generic_setxattr,
//	.getxattr	= generic_getxattr,
//	.listxattr	= ext3_listxattr,
//	.removexattr	= generic_removexattr,
//	.permission	= ext3_permission,
	/* FIXME: why doesn't ext4 support this for directory? */
//	.fallocate	= ext4_fallocate,
//	.fiemap		= ext4_fiemap,
};
