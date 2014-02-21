/*
 * tux3fuse: Mount tux3 in userspace.
 * Copyright (C) 2008 Conrad Meyer <konrad@tylerc.org>
 * Large portions completely stolen from Daniel Phillip's tux3.c.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Rewrite to fuse low level API by Tero Roponen <tero.roponen@gmail.com>
 */

/*
 * Compile: gcc -std=gnu99 buffer.c diskio.c fuse-tux3.c -D_FILE_OFFSET_BITS=64 -lfuse -o fuse-tux3
 * (-D_FILE_OFFSET_BITS=64 might be only on 64 bit platforms, not sure.)
 * Run:
 * 0. sudo mknod -m 666 /dev/fuse c 10 229
 *    Install libfuse and headers: sudo apt-get install libfuse-dev
 *    Install fuse-utils: sudo apt-get install fuse-utils
 *    build fuse kernel module: cd linux && make ;-)
 *    insert fuse kernel module: sudo insmod fs/fuse/fuse.ko
 * 1. Create a tux3 fs on testvol using some combination of dd
 *    and ./tux3 make testvol (or use make mkfs)
 * 2. Mount on foo/ like: ./tux3fuse testvol -f foo/ (-f for foreground)
 */

#include <linux/xattr.h>
#include "trace.h"
#include "tux3user.h"

#include <linux/fs.h>	/* for ioctl */

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <fuse/fuse_lowlevel.h>

#undef trace
#define trace trace_on

struct tux3fuse {
	struct sb *sb;
	char *volname;
};

static void tux3fuse_init(void *userdata, struct fuse_conn_info *conn)
{
	struct tux3fuse *tux3fuse = userdata;
	const char *volname = tux3fuse->volname;
	struct dev *dev;
	struct sb *sb;
	int err, fd;

	fd = open(volname, O_RDWR);
	if (fd < 0)
		strerror_exit(1, errno, "volume %s not found", volname);

	err = tux3_init_mem();
	if (err)
		goto error;

	err = -ENOMEM;
	dev = malloc(sizeof(*dev));
	if (!dev)
		goto error;
	/* dev->bits is still unknown. Note, some structure can't use yet. */
	*dev = (struct dev){ .fd = fd };

	sb = malloc(sizeof(*sb));
	if (!sb)
		goto error;
	*sb = *rapid_sb(dev);

	err = load_sb(sb);
	if (err)
		goto error;

	dev->bits = sb->blockbits;
	init_buffers(dev, 50 << 20, 2);

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}

	err = replay_stage3(rp, 1);
	if (err)
		goto error;

	tux3fuse->sb = sb;

	return;

error:
	strerror_exit(1, -err, "Eek!");
}

/* Stub methods */
static void tux3fuse_destroy(void *userdata)
{
	struct tux3fuse *tux3fuse = userdata;
	struct sb *sb = tux3fuse->sb;
	sync_super(sb);
	put_super(sb);
	tux3_exit_mem();

	if (tux3fuse->sb->dev)
		free(tux3fuse->sb->dev);
	if (tux3fuse->sb)
		free(tux3fuse->sb);
}

static struct sb *tux3fuse_get_sb(fuse_req_t req)
{
	struct tux3fuse *tux3fuse = fuse_req_userdata(req);
	return tux3fuse->sb;
}

static struct inode *tux3fuse_iget(struct sb *sb, fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		ino = TUX_ROOTDIR_INO;

	return tux3_iget(sb, ino);
}

static void tux3fuse_fill_stat(struct stat *stat, struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	*stat = (struct stat){
		/* .st_dev; */
		.st_ino		= tux_inode(inode)->inum,
		.st_mode	= inode->i_mode,
		.st_nlink	= inode->i_nlink,
		.st_uid		= i_uid_read(inode),
		.st_gid		= i_gid_read(inode),
		.st_rdev	= inode->i_rdev,
		.st_size	= inode->i_size,
		/* FIXME: might be better to use ->i_blkbits? */
		.st_blksize	= sb->blocksize,
		/* FIXME: need to implement ->i_blocks? */
		.st_blocks	= ALIGN(inode->i_size, sb->blocksize) >> 9,
		.st_atim	= inode->i_atime,
		.st_mtim	= inode->i_mtime,
		.st_ctim	= inode->i_ctime,
	};
}

static void tux3fuse_fill_ep(struct fuse_entry_param *ep, struct inode *inode)
{
	*ep = (struct fuse_entry_param){
		.ino		= tux_inode(inode)->inum,
		.generation	= 1,
		.attr_timeout	= 0.0,
		.entry_timeout	= 0.0,
	};
	tux3fuse_fill_stat(&ep->attr, inode);
}

static void tux3fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	trace("(%lx, '%s')", parent, name);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *dir, *inode;

	dir = tux3fuse_iget(sb, parent);
	if (IS_ERR(dir)) {
		fuse_reply_err(req, -PTR_ERR(dir));
		return;
	}

	inode = tuxopen(dir, name, strlen(name));
	iput(dir);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	struct fuse_entry_param ep;
	tux3fuse_fill_ep(&ep, inode);
	iput(inode);

	fuse_reply_entry(req, &ep);
}

static void tux3fuse_forget(fuse_req_t req, fuse_ino_t ino,
			    unsigned long nlookup)
{
	fuse_reply_none(req);
}

static void tux3fuse_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	struct stat stbuf;
	tux3fuse_fill_stat(&stbuf, inode);

	iput(inode);
	fuse_reply_attr(req, &stbuf, 0.0);
}

static void tux3fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			     int to_set, struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	change_begin(sb);

	tux3_iattrdirty(inode);

	if (to_set & FUSE_SET_ATTR_SIZE)
		__tuxtruncate(inode, attr->st_size);
	if (to_set & FUSE_SET_ATTR_MODE)
		inode->i_mode = attr->st_mode;
	if (to_set & FUSE_SET_ATTR_UID)
		i_uid_write(inode, attr->st_uid);
	if (to_set & FUSE_SET_ATTR_GID)
		i_gid_write(inode, attr->st_gid);
	if (to_set & FUSE_SET_ATTR_ATIME)
		inode->i_atime = attr->st_atim;
	if (to_set & FUSE_SET_ATTR_MTIME)
		inode->i_mtime = attr->st_mtim;
	if (to_set)
		tux3_mark_inode_dirty(inode);
	change_end(sb);

	struct stat stbuf;
	tux3fuse_fill_stat(&stbuf, inode);

	iput(inode);

	fuse_reply_attr(req, &stbuf, 0.0);
}

static void tux3fuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;
	int err;

	trace("(%lx)", ino);

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto error;
	}

	err = -ENOMEM;
	char *buf = malloc(inode->i_size);
	if (buf) {
		err = page_readlink(inode, buf, inode->i_size);
		if (!err) {
			buf[inode->i_size - 1] = '\0';
			fuse_reply_readlink(req, buf);
		}
		free(buf);
	}
	iput(inode);
error:
	if (err)
		fuse_reply_err(req, -err);
}

static struct inode *__tux3fuse_mknod(fuse_req_t req, fuse_ino_t parent,
				      const char *name, mode_t mode, dev_t rdev)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct sb *sb = tux3fuse_get_sb(req);
	struct tux_iattr iattr = {
		.uid	= make_kuid(&init_user_ns, ctx->uid),
		.gid	= make_kgid(&init_user_ns, ctx->gid),
		.mode	= mode,
	};
	struct inode *dir, *inode;

	dir = tux3fuse_iget(sb, parent);
	if (IS_ERR(dir))
		return dir;

	inode = __tuxmknod(dir, name, strlen(name), &iattr, rdev);
	iput(dir);
	return inode;
}

static void tux3fuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
			   mode_t mode, dev_t rdev)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct inode *inode;

	trace("(%lx, '%s', uid = %u, gid = %u, mode = %o, rdev %llx)",
	      parent, name, ctx->uid, ctx->gid, mode, (u64)rdev);

	inode = __tux3fuse_mknod(req, parent, name, mode, rdev);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	struct fuse_entry_param ep;
	tux3fuse_fill_ep(&ep, inode);
	iput(inode);

	fuse_reply_entry(req, &ep);
}

static void tux3fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			   mode_t mode)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct inode *inode;

	trace("(%lx, '%s', uid = %u, gid = %u, mode = %o)",
	      parent, name, ctx->uid, ctx->gid, mode);

	inode = __tux3fuse_mknod(req, parent, name, S_IFDIR | mode, 0);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	struct fuse_entry_param ep;
	tux3fuse_fill_ep(&ep, inode);
	iput(inode);

	fuse_reply_entry(req, &ep);
}

static void tux3fuse_link(fuse_req_t req, fuse_ino_t ino,
			  fuse_ino_t newparent, const char *newname)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *src_inode, *dir, *inode;
	int err;

	trace("(%lx, %lx, '%s')", ino, newparent, newname);

	src_inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(src_inode)) {
		err = -PTR_ERR(src_inode);
		goto error;
	}

	dir = tux3fuse_iget(sb, newparent);
	if (IS_ERR(dir)) {
		err = -PTR_ERR(dir);
		goto error_inode;
	}

	inode = __tuxlink(src_inode, dir, newname, strlen(newname));
	err = -PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		struct fuse_entry_param ep;
		tux3fuse_fill_ep(&ep, inode);
		iput(inode);

		fuse_reply_entry(req, &ep);
		err = 0;
	}

	iput(dir);
error_inode:
	iput(src_inode);
error:
	if (err)
		fuse_reply_err(req, -err);
}

static void tux3fuse_symlink(fuse_req_t req, const char *link,
			     fuse_ino_t parent, const char *name)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct sb *sb = tux3fuse_get_sb(req);
	struct tux_iattr iattr = {
		.uid	= make_kuid(&init_user_ns, ctx->uid),
		.gid	= make_kgid(&init_user_ns, ctx->gid),
	};
	struct inode *dir, *inode;
	int err;

	trace("('%s', %lx, '%s')", link, parent, name);

	dir = tux3fuse_iget(sb, parent);
	if (IS_ERR(dir)) {
		err = -PTR_ERR(dir);
		goto error;
	}

	inode = __tuxsymlink(dir, name, strlen(name), &iattr, link);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		struct fuse_entry_param ep;
		tux3fuse_fill_ep(&ep, inode);
		iput(inode);

		fuse_reply_entry(req, &ep);
		err = 0;
	}
	iput(dir);
error:
	if (err)
		fuse_reply_err(req, -err);
}

static void tux3fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *dir;
	int err;

	trace("(%lx, '%s')", parent, name);

	dir = tux3fuse_iget(sb, parent);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = tuxunlink(dir, name, strlen(name));
		iput(dir);
	}
	if (err)
		tux3_warn(sb, "Eek! %s", strerror(-err));

	fuse_reply_err(req, -err);
}

static void tux3fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *dir;
	int err;

	trace("(%lx, '%s')", parent, name);

	dir = tux3fuse_iget(sb, parent);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = tuxrmdir(dir, name, strlen(name));
		iput(dir);
	}
	if (err)
		tux3_warn(sb, "Eek! %s", strerror(-err));

	fuse_reply_err(req, -err);
}

static void tux3fuse_rename(fuse_req_t req,
			    fuse_ino_t parent, const char *name,
			    fuse_ino_t newparent, const char *newname)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *olddir, *newdir;
	int err;

	trace("(%lx, '%s', %lx, '%s')", parent, name, newparent, newname);

	olddir = tux3fuse_iget(sb, parent);
	if (IS_ERR(olddir)) {
		err = PTR_ERR(olddir);
		goto error;
	}
	newdir = tux3fuse_iget(sb, parent);
	if (IS_ERR(newdir)) {
		err = PTR_ERR(newdir);
		goto error_old;
	}

	err = tuxrename(olddir, name, strlen(name), newdir, newname,
			strlen(newname));

	iput(newdir);
error_old:
	iput(olddir);
error:
	fuse_reply_err(req, -err);
}

static void tux3fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
			    mode_t mode, struct fuse_file_info *fi)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct inode *inode;

	trace("(%lx, '%s', uid = %u, gid = %u, mode = %o)",
	      parent, name, ctx->uid, ctx->gid, mode);

	inode = __tux3fuse_mknod(req, parent, name, mode, 0);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	struct fuse_entry_param ep;
	tux3fuse_fill_ep(&ep, inode);

	fi->fh = (uint64_t)(unsigned long)inode;
	fuse_reply_create(req, &ep, fi);
}

static void tux3fuse_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	fi->fh = (uint64_t)(unsigned long)inode;
	fuse_reply_open(req, fi);
}

static void tux3fuse_flush(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	fuse_reply_err(req, 0);
}

static void tux3fuse_release(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	iput(inode);
	fuse_reply_err(req, 0);
}

/* Interface for readpage/readpages/direct_io */
static void tux3fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode, };
	int err;

	/* FIXME: better to use map_region() directly */
	trace("userspace tries to seek to %Li\n", (s64)offset);
	if (offset >= inode->i_size) {
		fuse_reply_buf(req, NULL, 0);
		return;
	}

	if (offset + size > inode->i_size)
		size = inode->i_size - offset;

	tuxseek(file, offset);

	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	int read = tuxread(file, buf, size);
	if (read < 0) {
		err = read;
		goto error;
	}
	assert(read <= size);

	fuse_reply_buf(req, buf, read);
	free(buf);
	return;

error:
	trace("Eek! %s", strerror(-err));
	fuse_reply_err(req, -err);
	free(buf);
}

static void tux3fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			   size_t size, off_t offset, struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode };

	/* FIXME: better to use map_region() directly */
	tuxseek(file, offset);

	int written = tuxwrite(file, buf, size);
	if (written < 0) {
		tux3_warn(tux_sb(inode->i_sb), "Eek! %s", strerror(-written));
		fuse_reply_err(req, -written);
		return;
	}

	fuse_reply_write(req, written);
}

static void tux3fuse_opendir(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	tux3fuse_open(req, ino, fi);
}

static void tux3fuse_releasedir(fuse_req_t req, fuse_ino_t ino,
				struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	tux3fuse_release(req, ino, fi);
}

struct fillstate {
	struct dir_context ctx;
	char *dirent;
	int done;
	u64 ino;
	unsigned type;
};

static int tux3fuse_filler(void *ctx, const char *name, int namelen,
			   loff_t offset, u64 ino, unsigned type)
{
	struct fillstate *state = ctx;
	if (state->done || namelen > TUX_NAME_LEN)
		return -EINVAL;
	trace("'%.*s'\n", namelen, name);
	memcpy(state->dirent, name, namelen);
	state->dirent[namelen] = 0;
	state->ino = ino;
	state->type = type;
	state->done = 1;
	return 0;
}

/* FIXME: this should return more than one dirent per tux_readdir */
static void tux3fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t offset, struct fuse_file_info *fi)
{
	trace("(%lx)", ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *dirfile = &(struct file){
		.f_inode = inode,
		.f_pos = offset,
	};
	char dirent[TUX_NAME_LEN + 1];
	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	while (dirfile->f_pos < dirfile->f_inode->i_size) {
		struct fillstate fstate = {
			.ctx = {
				.actor = tux3fuse_filler,
			},
			.dirent = dirent,
		};
		int err;

		fstate.ctx.pos = dirfile->f_pos;
		err = tux_readdir(dirfile, &fstate.ctx);
		dirfile->f_pos = fstate.ctx.pos;
		if (err) {
			fuse_reply_err(req, -err);
			free(buf);
			return;
		}
		struct stat stbuf = {
			.st_ino = fstate.ino,
			.st_mode = fstate.type,
		};
		size_t len = fuse_add_direntry(req, buf, size, dirent, &stbuf,
					       dirfile->f_pos);
		fuse_reply_buf(req, buf, len);
		free(buf);
		return;
	}

	fuse_reply_buf(req, NULL, 0);
	free(buf);
}

static void tux3fuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct statvfs statvfs = {
		.f_bsize	= sb->blocksize,
		.f_frsize	= sb->blocksize,
		.f_blocks	= sb->volblocks,
		.f_bfree	= sb->freeblocks,
		.f_bavail	= sb->freeblocks,
		.f_files	= MAX_INODES,
		.f_ffree	= sb->freeinodes,
		.f_favail	= sb->freeinodes,
		//.f_fsid	= ,
		//.f_flag	= ,
		.f_namemax	= TUX_NAME_LEN,
	};

	fuse_reply_statfs(req, &statvfs);
}

static void tux3fuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	/* Allow all accesses, for now */
	fuse_reply_err(req, 0);
}

static void tux3fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino,
			      int datasync, struct fuse_file_info *fi)
{
	struct sb *sb = tux3fuse_get_sb(req);
	/* FIXME: we should flush only this dir */
	sync_super(sb);
	fuse_reply_err(req, 0);
}

static void tux3fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			   struct fuse_file_info *fi)
{
	struct sb *sb = tux3fuse_get_sb(req);
	/* FIXME: we should flush only this file */
	sync_super(sb);
	fuse_reply_err(req, 0);
}

/*
 * FIXME: If we didn't return error for POSIX acl, userland will use
 * POSIX acl instead of chmod, etc. So, return error if it was not
 * 'user.' or 'trusted.'. We need to implement others.
 */
static int xattr_prefix_check(const char *name)
{
	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) {
		if (strlen(name) <= XATTR_TRUSTED_PREFIX_LEN)
			return -EINVAL;
		return 0;
	}
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (strlen(name) <= XATTR_USER_PREFIX_LEN)
			return -EINVAL;
		return 0;
	}
	return -EOPNOTSUPP;
}

static void tux3fuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      const char *value, size_t size, int flags)
{
	trace("(%lx, '%s'='%s')", ino, name, value);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;
	int err;

	err = xattr_prefix_check(name);
	if (err) {
		fuse_reply_err(req, -err);
		return;
	}

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	err = set_xattr(inode, name, strlen(name), value, size, flags);
	iput(inode);

	fuse_reply_err(req, -err);
}

static void tux3fuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      size_t maxsize)
{
	trace("(%lx, '%s')", ino, name);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;
	int err;

	err = xattr_prefix_check(name);
	if (err) {
		fuse_reply_err(req, -err);
		return;
	}

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	void *data = NULL;
	if (maxsize) {
		if (!(data = malloc(maxsize))) {
			fuse_reply_err(req, ENOMEM);
			goto out;
		}
	}
	int size = get_xattr(inode, name, strlen(name), data, maxsize);
	if (size < 0)
		fuse_reply_err(req, -size);
	else if (!maxsize)
		fuse_reply_xattr(req, size);
	else
		fuse_reply_buf(req, data, size);

	if (data)
		free(data);
out:
	iput(inode);
}

static void tux3fuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	trace("(%lx, %zu)", ino, size);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	char *buf = NULL;
	if (size) {
		buf = malloc(size);
		if (!buf) {
			fuse_reply_err(req, ENOMEM);
			iput(inode);
			return;
		}
	}

	int len = list_xattr(inode, buf, size);
	trace("listxattr-buffer: %s", buf);
	iput(inode);

	if (len < 0)
		fuse_reply_err(req, -len);
	else {
		if (size)
			fuse_reply_buf(req, buf, len);
		else
			fuse_reply_xattr(req, len);
	}

	if (buf)
		free(buf);
}

static void tux3fuse_removexattr(fuse_req_t req, fuse_ino_t ino,
				 const char *name)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;
	int err;

	trace("(%lx, '%s')", ino, name);

	err = xattr_prefix_check(name);
	if (err) {
		fuse_reply_err(req, -err);
		return;
	}

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	err = del_xattr(inode, name, strlen(name));
	iput(inode);

	fuse_reply_err(req, -err);
}

#ifdef NEED_REMOTE_LOCKS
/* We don't need to hook getlk/setlk */
static void tux3fuse_getlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock)
{
	struct sb *sb = tux3fuse_get_sb(req);
	tux3_warn(sb, "not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_setlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock,
			   int sleep)
{
	struct sb *sb = tux3fuse_get_sb(req);
	tux3_warn(sb, "not implemented");
	fuse_reply_err(req, ENOSYS);
}
#endif /* !NEED_REMOTE_LOCKS */

/* This is only used if 'blkdev' option was passed to fuse */
static void tux3fuse_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
			  uint64_t idx)
{
	struct sb *sb = tux3fuse_get_sb(req);
	tux3_warn(sb, "not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_ioctl(fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
			   struct fuse_file_info *fi, unsigned flags,
			   const void *in_buf, size_t in_bufsz,
			   size_t out_bufsz)
{
	trace("(%lx, 0x%08x, %p, %p, %x, %p, %zu, %zu)",
	      ino, cmd, arg, fi, flags, in_buf, in_bufsz, out_bufsz);

	switch (cmd) {
	case FS_IOC_GETFLAGS:
	case FS_IOC_SETFLAGS:
#if BITS_PER_LONG == 64
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
#endif
		fuse_reply_err(req, ENOTTY);
		return;
	}

	fuse_reply_err(req, ENOTTY);
}

static struct fuse_lowlevel_ops tux3_ops = {
	.init		= tux3fuse_init,
	.destroy	= tux3fuse_destroy,
	.lookup		= tux3fuse_lookup,
	.forget		= tux3fuse_forget,
	.getattr	= tux3fuse_getattr,
	.setattr	= tux3fuse_setattr,
	.readlink	= tux3fuse_readlink,
	.mknod		= tux3fuse_mknod,
	.mkdir		= tux3fuse_mkdir,
	.unlink		= tux3fuse_unlink,
	.rmdir		= tux3fuse_rmdir,
	.symlink	= tux3fuse_symlink,
	.rename		= tux3fuse_rename,
	.link		= tux3fuse_link,
	.open		= tux3fuse_open,
	.read		= tux3fuse_read,
	.write		= tux3fuse_write,
	.flush		= tux3fuse_flush,
	.release	= tux3fuse_release,
	.fsync		= tux3fuse_fsync,
	.opendir	= tux3fuse_opendir,
	.readdir	= tux3fuse_readdir,
	.releasedir	= tux3fuse_releasedir,
	.fsyncdir	= tux3fuse_fsyncdir,
	.statfs		= tux3fuse_statfs,
	.setxattr	= tux3fuse_setxattr,
	.getxattr	= tux3fuse_getxattr,
	.listxattr	= tux3fuse_listxattr,
	.removexattr	= tux3fuse_removexattr,
	.access		= tux3fuse_access,
	.create		= tux3fuse_create,
#ifdef NEED_REMOTE_LOCKS
	.getlk		= tux3fuse_getlk,
	.setlk		= tux3fuse_setlk,
#endif
	.bmap		= tux3fuse_bmap,
	.ioctl		= tux3fuse_ioctl,
	/* .poll */
};

enum {
	/* tux3fuse options */
	FUSE_OPT_KEY_TUX3_HELP,
};

static struct fuse_opt tux3fuse_options[] = {
	FUSE_OPT_KEY("-h",	FUSE_OPT_KEY_TUX3_HELP),
	FUSE_OPT_KEY("--help",	FUSE_OPT_KEY_TUX3_HELP),
	FUSE_OPT_END
};

static int tux3fuse_parse_options(void *data, const char *arg,
				  int key, struct fuse_args *outargs)
{
	struct tux3fuse *tux3fuse = data;

	/*
	 * We take the first two NONOPT options as
	 * the volume name and the mount point.
	 */
	if (key == FUSE_OPT_KEY_NONOPT) {
		if (!tux3fuse->volname) {
			tux3fuse->volname = canonicalize_file_name(arg);
			if (!tux3fuse->volname) {
				fprintf(stderr, "Volume not found: %s: %s\n",
					arg, strerror(errno));
				return -1;
			}
			return 0; /* We handled this option */
		}
	} else if (key == FUSE_OPT_KEY_TUX3_HELP) {
		fprintf(stderr,
			"Usage: %s [options] <volume> <mount-point>\n"
			"\n"
			"Options:\n"
			"    -o opt,[opt...]        mount options\n"
			"    -h   --help            print help\n"
			"    -V   --version         print version\n"
			"\n", outargs->argv[0]);
		return fuse_opt_add_arg(outargs, "-ho");
	}

	/* Pass all other options to FUSE. */
	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *fc;
	struct fuse_session *fs;
	char *mountpoint;
	int foreground;
	int err = -1;

	struct tux3fuse tux3fuse = {};

	if (argc < 3) {
		/* Print usage */
		struct fuse_args usage_args = FUSE_ARGS_INIT(0, NULL);
		if (fuse_opt_add_arg(&usage_args, argv[0]) == -1 ||
		    fuse_opt_add_arg(&usage_args, "-h") == -1)
			goto error;

		args = usage_args;
	}

	if (fuse_opt_parse(&args, &tux3fuse, tux3fuse_options,
			   tux3fuse_parse_options) == -1)
		goto error;

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, &foreground) == -1)
		goto error;

	fc = fuse_mount(mountpoint, &args);
	if (!fc)
		goto error;

	fs = fuse_lowlevel_new(&args, &tux3_ops, sizeof(tux3_ops), &tux3fuse);
	if (fs) {
		if (fuse_set_signal_handlers(fs) != -1) {
			fuse_session_add_chan(fs, fc);

			if (!foreground)
				printf("Running in background\n");
			fuse_daemonize(foreground);

			err = fuse_session_loop(fs);

			fuse_remove_signal_handlers(fs);
			fuse_session_remove_chan(fc);
		}
		fuse_session_destroy(fs);
	}

	fuse_unmount(mountpoint, fc);

error:
	fuse_opt_free_args(&args);
	if (tux3fuse.volname)
		free(tux3fuse.volname);

	return err ? 1 : 0;
}
