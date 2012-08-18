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

//#include <sys/xattr.h>
#include "trace.h"
#include "tux3user.h"

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
	int fd;

	fd = open(volname, O_RDWR);
	if (fd < 0) {
		error("volume %s not found", volname);
		goto error;
	}

	dev = malloc(sizeof(*dev));
	if (!dev)
		goto error;
	/* dev->bits is still unknown. Note, some structure can't use yet. */
	*dev = (struct dev){ .fd = fd };

	sb = malloc(sizeof(*sb));
	if (!sb)
		goto error;
	*sb = *rapid_sb(dev);

	if ((errno = -load_sb(sb)))
		goto error;
	dev->bits = sb->blockbits;
	init_buffers(dev, 50 << 20, 2);

	sb->volmap = tux_new_volmap(sb);
	if (!sb->volmap) {
		errno = ENOMEM;
		goto error;
	}
	sb->logmap = tux_new_logmap(sb);
	if (!sb->logmap) {
		errno = ENOMEM;
		goto error;
	}

	struct replay *rp = replay_stage1(sb);
	if (IS_ERR(rp)) {
		errno = -PTR_ERR(rp);
		goto error;
	}

	sb->bitmap = iget_or_create_inode(sb, TUX_BITMAP_INO);
	if (IS_ERR(sb->bitmap)) {
		errno = -PTR_ERR(sb->bitmap);
		goto error;
	}
	sb->rootdir = tux3_iget(sb, TUX_ROOTDIR_INO);
	if (IS_ERR(sb->rootdir)) {
		errno = -PTR_ERR(sb->rootdir);
		goto error;
	}
	sb->atable = tux3_iget(sb, TUX_ATABLE_INO);
	if (IS_ERR(sb->atable)) {
		errno = -PTR_ERR(sb->atable);
		goto error;
	}

	if ((errno = -replay_stage2(rp)))
		goto error;
	if ((errno = -replay_stage3(rp, 1)))
		goto error;

	tux3fuse->sb = sb;

	return;

error:
	warn("Eek! %s", strerror(errno));
	exit(1);
}

/* Stub methods */
static void tux3fuse_destroy(void *userdata)
{
	struct tux3fuse *tux3fuse = userdata;
	struct sb *sb = tux3fuse->sb;
	sync_super(sb);
	put_super(sb);

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
		.st_ino		= inode->inum,
		.st_mode	= inode->i_mode,
		.st_nlink	= inode->i_nlink,
		.st_uid		= inode->i_uid,
		.st_gid		= inode->i_gid,
		.st_rdev	= inode->i_rdev,
		.st_size	= inode->i_size,
		/* FIXME: might be better to use ->i_blkbits? */
		.st_blksize	= sb->blocksize,
		/* FIXME: need to implement ->i_blocks? */
		.st_blocks	=
			((inode->i_size + sb->blockmask) & ~(loff_t)sb->blockmask) >> 9,
		.st_atim	= inode->i_atime,
		.st_mtim	= inode->i_mtime,
		.st_ctim	= inode->i_ctime,
	};
}

static void tux3fuse_fill_ep(struct fuse_entry_param *ep, struct inode *inode)
{
	*ep = (struct fuse_entry_param){
		.ino		= inode->inum,
		.generation	= 1,
		.attr_timeout	= 0.0,
		.entry_timeout	= 0.0,
	};
	tux3fuse_fill_stat(&ep->attr, inode);
}

static void tux3fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	trace("(%Lx, '%s')", (L)parent, name);
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
	trace("(%Lx)", (L)ino);
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
	trace("(%Lx)", (L)ino);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	if (to_set & FUSE_SET_ATTR_MODE)
		inode->i_mode = attr->st_mode;
	if (to_set & FUSE_SET_ATTR_UID)
		inode->i_uid = attr->st_uid;
	if (to_set & FUSE_SET_ATTR_GID)
		inode->i_gid = attr->st_gid;
	if (to_set & FUSE_SET_ATTR_ATIME)
		inode->i_atime = attr->st_atim;
	if (to_set & FUSE_SET_ATTR_MTIME)
		inode->i_mtime = attr->st_mtim;
	if (to_set & FUSE_SET_ATTR_SIZE)
		tuxtruncate(inode, attr->st_size);
	if (to_set)
		mark_inode_dirty(inode);

	struct stat stbuf;
	tux3fuse_fill_stat(&stbuf, inode);

	iput(inode);

	fuse_reply_attr(req, &stbuf, 0.0);
}

static void tux3fuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static struct inode *__tux3fuse_mknod(fuse_req_t req, fuse_ino_t parent,
				      const char *name, mode_t mode, dev_t rdev)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	struct sb *sb = tux3fuse_get_sb(req);
	struct tux_iattr iattr = {
		.uid	= ctx->uid,
		.gid	= ctx->gid,
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

	trace("(%Lx, '%s', uid = %u, gid = %u, mode = %o, rdev %llx)",
	      (L)parent, name, ctx->uid, ctx->gid, mode, (L)rdev);

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

	trace("(%Lx, '%s', uid = %u, gid = %u, mode = %o)",
	      (L)parent, name, ctx->uid, ctx->gid, mode);

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

	trace("(%Lx, %Lx, '%s')", (L)ino, (L)newparent, newname);

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

static void tux3fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *dir;
	int err;

	trace("(%Lx, '%s')", (L)parent, name);

	dir = tux3fuse_iget(sb, parent);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = tuxunlink(dir, name, strlen(name));
		iput(dir);
	}
	if (err)
		warn("Eek! %s", strerror(-err));

	fuse_reply_err(req, -err);
}

static void tux3fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *dir;
	int err;

	trace("(%Lx, '%s')", (L)parent, name);

	dir = tux3fuse_iget(sb, parent);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = tuxrmdir(dir, name, strlen(name));
		iput(dir);
	}
	if (err)
		warn("Eek! %s", strerror(-err));

	fuse_reply_err(req, -err);
}

static void tux3fuse_rename(fuse_req_t req,
			    fuse_ino_t parent, const char *name,
			    fuse_ino_t newparent, const char *newname)
{
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *olddir, *newdir;
	int err;

	trace("(%Lx, '%s', %Lx, '%s')", (L)parent, name, (L)newparent, newname);

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

	trace("(%Lx, '%s', uid = %u, gid = %u, mode = %o)",
	      (L)parent, name, ctx->uid, ctx->gid, mode);

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
	trace("(%Lx)", (L)ino);
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
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_release(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	trace("(%Lx)", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	iput(inode);
	fuse_reply_err(req, 0);
}

/* Interface for readpage/readpages/direct_io */
static void tux3fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	trace("(%Lx)", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode, };

	/* FIXME: better to use map_region() directly */
	trace("userspace tries to seek to %Li\n", (L)offset);
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
		errno = -read;
		goto error;
	}
	assert(read <= size);

	fuse_reply_buf(req, buf, read);
	free(buf);
	return;

error:
	trace("Eek! %s", strerror(errno));
	fuse_reply_err(req, errno);
	free(buf);
}

static void tux3fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			   size_t size, off_t offset, struct fuse_file_info *fi)
{
	trace("(%Lx)", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode };

	/* FIXME: better to use map_region() directly */
	tuxseek(file, offset);

	int written = tuxwrite(file, buf, size);
	if (written < 0) {
		errno = -written;
		warn("Eek! %s", strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	fuse_reply_write(req, written);
}

static void tux3fuse_opendir(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	trace("(%Lx)", (L)ino);
	tux3fuse_open(req, ino, fi);
}

static void tux3fuse_releasedir(fuse_req_t req, fuse_ino_t ino,
				struct fuse_file_info *fi)
{
	trace("(%Lx)", (L)ino);
	tux3fuse_release(req, ino, fi);
}

struct fillstate { char *dirent; int done; u64 ino; unsigned type; };

static int tux3fuse_filler(void *info, const char *name, int namelen,
			   loff_t offset, u64 ino, unsigned type)
{
	struct fillstate *state = info;
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
	trace("(%Lx)", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *dirfile = &(struct file){ .f_inode = inode, .f_pos = offset };
	char dirent[TUX_NAME_LEN + 1];
	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	while (dirfile->f_pos < dirfile->f_inode->i_size) {
		struct fillstate fstate = { .dirent = dirent };
		if ((errno = -tux_readdir(dirfile, &fstate, tux3fuse_filler))) {
			fuse_reply_err(req, errno);
			free(buf);
			return;
		}
		struct stat stbuf = {
			.st_ino = fstate.ino,
			.st_mode = fstate.type,
		};
		size_t len = fuse_add_direntry(req, buf, size, dirent, &stbuf, dirfile->f_pos);
		fuse_reply_buf(req, buf, len);
		free(buf);
		return;
	}

	fuse_reply_buf(req, NULL, 0);
	free(buf);
}

static void tux3fuse_symlink(fuse_req_t req, const char *link,
			     fuse_ino_t parent, const char *name)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	/* Allow all accesses, for now */
	fuse_reply_err(req, 0);
}

static void tux3fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino,
			      int datasync, struct fuse_file_info *fi)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			   struct fuse_file_info *fi)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      const char *value, size_t size, int flags)
{
	trace("(%Lx, '%s'='%s')", (L)ino, name, value);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	int err = set_xattr(inode, name, strlen(name), value, size, flags);
	iput(inode);

	fuse_reply_err(req, -err);
}

static void tux3fuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      size_t maxsize)
{
	trace("(%Lx, '%s')", (L)ino, name);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

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
	trace("(%Lx/%zu)", (L)ino, size);
	struct sb *sb = tux3fuse_get_sb(req);
	struct inode *inode;

	inode = tux3fuse_iget(sb, ino);
	if (IS_ERR(inode)) {
		fuse_reply_err(req, -PTR_ERR(inode));
		return;
	}

	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		iput(inode);
		return;
	}

	int len = xattr_list(inode, buf, size);
	trace("listxattr-buffer:%s", buf);
	iput(inode);

	fuse_reply_buf(req, buf, len);
	free(buf);
}

static void tux3fuse_removexattr(fuse_req_t req, fuse_ino_t ino,
				 const char *name)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_getlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_setlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock,
			   int sleep)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3fuse_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
			  uint64_t idx)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
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
	.getlk		= tux3fuse_getlk,
	.setlk		= tux3fuse_setlk,
	.bmap		= tux3fuse_bmap,
	/* .ioctl */
	/* .poll */
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
	struct fuse_chan *fc;
	struct fuse_session *fs;
	char *mountpoint;
	int foreground;
	int err = -1;

	if (argc < 3)
		error("usage: %s <volname> <mountpoint> [fuse opts]", argv[0]);

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, &foreground) == -1)
		goto error;

	fc = fuse_mount(mountpoint, &args);
	if (!fc)
		goto error;

	struct tux3fuse tux3fuse = {
		.volname = argv[1],
	};
	fs = fuse_lowlevel_new(&args, &tux3_ops, sizeof(tux3_ops), &tux3fuse);
	if (fs) {
		if (fuse_set_signal_handlers(fs) != -1) {
			fuse_session_add_chan(fs, fc);
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

	return err ? 1 : 0;
}
