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

struct inode *tuxopen(struct inode *dir, const char *name, unsigned len)
{
	struct dentry dentry = {
		.d_name.name = (unsigned char *)name,
		.d_name.len = len,
	};
	struct dentry *result;

	result = tux3_lookup(dir, &dentry, NULL);
	if (result && IS_ERR(result))
		return ERR_CAST(result);
	assert(result == NULL);

	if (!dentry.d_inode)
		return ERR_PTR(-ENOENT);

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

	entry = tux_find_dirent(dir, dentry.d_name.name, dentry.d_name.len,
				&buffer);
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
