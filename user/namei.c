/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Original copyright (c) 2012 OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#include "kernel/namei.c"

static int tuxlookup(struct inode *dir, struct dentry *dentry)
{
	struct dentry *result;

	result = tux3_lookup(dir, dentry, NULL);
	if (result && IS_ERR(result))
		return PTR_ERR(result);
	assert(result == NULL);

	if (!dentry->d_inode)
		return -ENOENT;

	return 0;
}

struct inode *tuxopen(struct inode *dir, const char *name, unsigned len)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	int err;

	err = tuxlookup(dir, &dentry);
	if (err)
		return ERR_PTR(err);

	return dentry.d_inode;
}

struct inode *tuxcreate(struct inode *dir, const char *name, unsigned len,
			struct tux_iattr *iattr)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	struct buffer_head *buffer;
	tux_dirent *entry;

	/*
	 * FIXME: we can find space with existent check
	 */

	entry = tux_find_dirent(dir, &dentry.d_name, &buffer);
	if (!IS_ERR(entry)) {
		blockput(buffer);
		return ERR_PTR(-EEXIST); // should allow create of a file that already exists!!!
	}
	if (PTR_ERR(entry) != -ENOENT)
		return ERR_CAST(entry);

	int err = __tux3_mknod(dir, &dentry, iattr, 0);
	if (err)
		return ERR_PTR(err);

	return dentry.d_inode;
}

int tuxunlink(struct inode *dir, const char *name, unsigned len)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	int err;

	/*
	 * FIXME: we can cache dirent position by tuxlookup(), and
	 * tux3_unlink() can use it.
	 */

	err = tuxlookup(dir, &dentry);
	if (err)
		return err;

	err = tux3_unlink(dir, &dentry);

	/* This iput() will truncate inode if i_nlink == 0 && i_count == 1 */
	iput(dentry.d_inode);

	return err;
}

int tuxrmdir(struct inode *dir, const char *name, unsigned len)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	int err;

	/*
	 * FIXME: we can cache dirent position by tuxlookup(), and
	 * tux3_unlink() can use it.
	 */

	err = tuxlookup(dir, &dentry);
	if (err)
		return err;

	err = -ENOTDIR;
	if (S_ISDIR(dentry.d_inode->i_mode))
		err = tux3_rmdir(dir, &dentry);

	/* This iput() will truncate inode if i_nlink == 0 && i_count == 1 */
	iput(dentry.d_inode);

	return err;
}
