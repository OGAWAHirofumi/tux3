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

struct inode *__tuxmknod(struct inode *dir, const char *name, unsigned len,
			 struct tux_iattr *iattr, dev_t rdev)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	int err;

	err = __tux3_mknod(dir, &dentry, iattr, rdev);
	if (err)
		return ERR_PTR(err);

	return dentry.d_inode;
}

struct inode *tuxcreate(struct inode *dir, const char *name, unsigned len,
			struct tux_iattr *iattr)
{
	struct qstr qstr = {
		.name = (unsigned char *)name,
		.len = len,
	};
	int err;

	/*
	 * FIXME: we can find space with existent check
	 */

	err = tux_check_exist(dir, &qstr);
	if (err) {
		if (err == -EEXIST) {
			// should allow create of a file that already exists!!!
		}
		return ERR_PTR(err);
	}

	return __tuxmknod(dir, name, len, iattr, 0);
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

int tuxsymlink(struct inode *dir, const char *name, unsigned len,
	       struct tux_iattr *iattr, const char *symname)
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
	if (err)
		return err;

	err = __tux3_symlink(dir, &dentry, iattr, symname);
	if (!err)
		iput(dentry.d_inode);

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

int tuxrename(struct inode *old_dir, const char *old_name, unsigned old_len,
	      struct inode *new_dir, const char *new_name, unsigned new_len)
{
	struct dentry old = {
		.d_name.name = (unsigned char *)old_name,
		.d_name.len = old_len,
	};
	struct dentry new = {
		.d_name.name = (unsigned char *)new_name,
		.d_name.len = new_len,
	};
	int err;

	/*
	 * FIXME: we can cache dirent position by tuxlookup(), and
	 * tux3_rename() can use it.
	 */

	err = tuxlookup(old_dir, &old);
	if (err)
		return err;

	err = tuxlookup(new_dir, &new);
	if (err && err != -ENOENT)
		goto error_old;

	/* FIXME: check is not enough */
	err = 0;
	if (old.d_inode == new.d_inode)
		goto out;
	if (new.d_inode) {
		if (S_ISDIR(old.d_inode->i_mode)) {
			if (!S_ISDIR(new.d_inode->i_mode)) {
				err = -ENOTDIR;
				goto out;
			}
		} else {
			if (S_ISDIR(new.d_inode->i_mode)) {
				err = -EISDIR;
				goto out;
			}
		}
	}

	err = tux3_rename(old_dir, &old, new_dir, &new);
out:
	if (new.d_inode)
		iput(new.d_inode);
error_old:
	iput(old.d_inode);

	return err;
}
