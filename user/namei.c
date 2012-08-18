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

static int tux_check_exist(struct inode *dir, struct qstr *qstr)
{
	struct buffer_head *buffer;
	tux_dirent *entry;

	entry = tux_find_dirent(dir, qstr, &buffer);
	if (!IS_ERR(entry)) {
		blockput(buffer);
		return -EEXIST;
	}
	if (PTR_ERR(entry) != -ENOENT)
		return PTR_ERR(entry);

	return 0;
}

struct inode *tuxcreate(struct inode *dir, const char *name, unsigned len,
			struct tux_iattr *iattr)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	int err;

	/*
	 * FIXME: we can find space with existent check
	 */

	err = tux_check_exist(dir, &dentry.d_name);
	if (err) {
		if (err == -EEXIST) {
			// should allow create of a file that already exists!!!
		}
		return ERR_PTR(err);
	}

	err = __tux3_mknod(dir, &dentry, iattr, 0);
	if (err)
		return ERR_PTR(err);

	return dentry.d_inode;
}

int tuxlink(struct inode *dir, const char *srcname, unsigned srclen,
	    const char *dstname, unsigned dstlen)
{
	struct dentry src = {
		.d_name.name = (unsigned char *)srcname,
		.d_name.len = srclen,
	};
	struct dentry dst = {
		.d_name.name = (unsigned char *)dstname,
		.d_name.len = dstlen,
	};
	int err;

	err = tuxlookup(dir, &src);
	if (err)
		return err;
	if (S_ISDIR(src.d_inode->i_mode)) {
		err = -EPERM;
		goto error_src;
	}
	/* Orphaned inode. We shouldn't grab this. */
	if (src.d_inode->i_nlink == 0) {
		err = -ENOENT;
		goto error_src;
	}

	/*
	 * FIXME: we can find space with existent check
	 */

	err = tux_check_exist(dir, &dst.d_name);
	if (err)
		goto error_src;

	err = tux3_link(&src, dir, &dst);
	if (!err) {
		assert(dst.d_inode == src.d_inode);
		iput(dst.d_inode);
	}
error_src:
	iput(src.d_inode);

	return err;
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
