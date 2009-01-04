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
 * 1. Create a tux3 fs on __fuse__tux3fs using some combination of dd
 *    and ./tux3 make __fuse__tux3fs.
 * 2. Mount on foo/ like: ./fuse-tux3 __fuse__tux3fs -f foo/ (-f for foreground)
 */

//#include <sys/xattr.h>
#include "trace.h"
#include "tux3.h"

#define FUSE_USE_VERSION 27
#include <fuse.h>
#include <fuse/fuse_lowlevel.h>

#define include_inode_c
#include "inode.c"

static u64 volsize;
static struct sb *sb;
static struct dev *dev;

static struct inode *open_fuse_ino(fuse_ino_t ino)
{
	struct inode *inode;
	if (ino == FUSE_ROOT_ID)
		return sb->rootdir;

	inode = iget(sb, ino);
	if (inode) {
		if (!open_inode(inode))
			return inode;
		free_inode(inode);
	}

	return NULL;
}

static void tux3_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fprintf(stderr, "tux3_lookup(%Lx, '%s')\n", (L)parent, name);
	struct inode *inode = tuxopen(sb->rootdir, name, strlen(name));

	if (inode) {
		struct fuse_entry_param ep = {
			.attr = {
				.st_ino   = inode->inum,
				.st_mode  = inode->i_mode,
				.st_ctim = inode->i_ctime,
				.st_mtim = inode->i_mtime,
				.st_atim = inode->i_atime,
				.st_size  = inode->i_size,
				.st_uid   = inode->i_uid,
				.st_gid   = inode->i_gid,
				.st_nlink = inode->i_nlink,
			},

			.ino = inode->inum,
			.generation = 1,
			.attr_timeout = 0.0,
			.entry_timeout = 0.0,
		};

		tuxclose(inode);

		fuse_reply_entry(req, &ep);
	} else {
		fuse_reply_err(req, ENOENT);
	}
}

static void tux3_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_open(%Lx)\n", (L)ino);
	struct inode *inode = open_fuse_ino(ino);
	if (inode) {
		fi->flags |= 0666;
		fi->fh = (uint64_t)(unsigned long)inode;
		fuse_reply_open(req, fi);
	} else {
		fuse_reply_err(req, ENOENT);
	}
}

static void tux3_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_read(%Lx)\n", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode };

	printf("userspace tries to seek to %Li\n", (L)offset);
	if (offset >= inode->i_size)
	{
		printf("EOF!\n");
		fuse_reply_err(req, EINVAL);
		return;
	}
	tuxseek(file, offset);

	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	int read = tuxread(file, buf, size);
	if (read < 0)
	{
		errno = -read;
		goto eek;
	}

	if (offset + read > inode->i_size)
	{
		fuse_reply_err(req, EINVAL);
		free(buf);
		return;
	}

	fuse_reply_buf(req, buf, read);
	free(buf);
	return;

eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	fuse_reply_err(req, errno);
	free(buf);
}

static void tux3_create(fuse_req_t req, fuse_ino_t parent, const char *name,
	mode_t mode, struct fuse_file_info *fi)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	fprintf(stderr, "tux3_create(%Lx, '%s', uid = %u, gid = %u, mode = %o)\n", (L)parent, name, ctx->uid, ctx->gid, mode);
	struct inode *inode = tuxcreate(sb->rootdir, name, strlen(name),
		&(struct tux_iattr){ .uid = ctx->uid, .gid = ctx->gid, .mode = mode });
	if (inode) {
		struct fuse_entry_param fep = {
			.attr = {
				.st_ino   = inode->inum,
				.st_mode  = inode->i_mode,
				.st_ctim = inode->i_ctime,
				.st_mtim = inode->i_mtime,
				.st_atim = inode->i_atime,
				.st_size  = inode->i_size,
				.st_uid   = inode->i_uid,
				.st_gid   = inode->i_gid,
				.st_nlink = inode->i_nlink,
			},

			.ino = inode->inum,
			.generation = 1,
			.attr_timeout = 0.0,
			.entry_timeout = 0.0,
		};

		fi->fh = (uint64_t)(unsigned long)inode;
		fuse_reply_create(req, &fep, fi);
	} else {
		fuse_reply_err(req, ENOMEM);
	}
}

static void tux3_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
	size_t size, off_t offset, struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_write(%Lx)\n", (L)ino);
	struct inode *inode = (struct inode *)(unsigned long)fi->fh;
	struct file *file = &(struct file){ .f_inode = inode };

	if (offset) {
		u64 seek = offset;
		printf("seek to %Li\n", (L)seek);
		tuxseek(file, seek);
	}

	int written = 0;
	if ((written = tuxwrite(file, buf, size)) < 0)
	{
		errno = -written;
		goto eek;
	}

	tuxsync(inode);
	if ((errno = -sync_super(sb)))
		goto eek;

	fuse_reply_write(req, written);
	return;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	fuse_reply_err(req, errno);
}

static void _tux3_getattr(struct inode *inode, struct stat *st)
{
	*st = (struct stat){
		.st_ino   = inode->inum,
		.st_mode  = inode->i_mode,
		.st_size  = inode->i_size,
		.st_uid   = inode->i_uid,
		.st_gid   = inode->i_gid,
		.st_nlink = inode->i_nlink,
		.st_ctim = inode->i_ctime,
		.st_mtim = inode->i_mtime,
		.st_atim = inode->i_atime,
	};
}

static void tux3_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_getattr(%Lx)\n", (L)ino);
	struct inode *inode = open_fuse_ino(ino);
	if (inode) {
		struct stat stbuf;
		_tux3_getattr(inode, &stbuf);
		fuse_reply_attr(req, &stbuf, 0.0);
	} else {
		fuse_reply_err(req, ENOENT);
	}
}

static void tux3_opendir(fuse_req_t req, fuse_ino_t ino,
	struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_opendir(%Lx)\n", (L)ino);
	struct inode *inode = open_fuse_ino(ino);
	if (inode) {
		fi->fh = (uint64_t)(unsigned long)inode;
		fuse_reply_open(req, fi);
	} else {
		fuse_reply_err(req, ENOENT);
	}
}

static void tux3_releasedir(fuse_req_t req, fuse_ino_t ino,
	struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_releasedir(%Lx)\n", (L)ino);
	if (ino != FUSE_ROOT_ID) {
		struct inode *inode = (struct inode *)(unsigned long)fi->fh;
		tuxclose(inode);
	}
	fuse_reply_err(req, 0); /* Success */
}

struct fillstate { char *dirent; int done; unsigned inode; unsigned type; };

int tux3_filler(void *info, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type)
{
	struct fillstate *state = info;
	if (state->done || namelen > TUX_NAME_LEN)
		return -EINVAL;
	printf("'%.*s'\n", namelen, name);
	memcpy(state->dirent, name, namelen);
	state->dirent[namelen] = 0;
	state->inode = inode;
	state->type = type;
	state->done = 1;
	return 0;
}

/* FIXME: this should return more than one dirent per tux_readdir */
static void tux3_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_readdir(%Lx)\n", (L)ino);
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
		if ((errno = -tux_readdir(dirfile, &fstate, tux3_filler))) {
			fuse_reply_err(req, errno);
			free(buf);
			return;
		}
		struct stat stbuf = {
			.st_ino = fstate.inode,
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

static void tux3_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fprintf(stderr, "tux3_unlink(%Lx, '%s')\n", (L)parent, name);
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_entry(sb->rootdir, name, strlen(name), &buffer);
	if (IS_ERR(entry)) {
		errno = -PTR_ERR(entry);
		goto eek;
	}
	inum_t inum = from_be_u64(entry->inum);
	//brelse(buffer); //brelse: Failed assertion "buffer->count"!
	struct inode inode = { .i_sb = sb, .inum = inum, };

	if ((errno = -open_inode(&inode)))
		goto eek;
	if ((errno = -tree_chop(&inode.btree, &(struct delete_info){ .key = 0 }, -1)))
		goto eek;
	if ((errno = -tux_delete_entry(buffer, entry)))
		goto eek;

	fuse_reply_err(req, 0);
	return;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	fuse_reply_err(req, errno);
}

static void tux3_init(void *data, struct fuse_conn_info *conn)
{
	const char *volname = data;
	int fd;
	if ((fd = open(volname, O_RDWR, S_IRWXU)) < 0)
		error("volume %s not found", volname);

	volsize = 0;
	if (fdsize64(fd, &volsize))
		error("fdsize64 failed for '%s' (%s) %i", volname, strerror(errno), fd);
	dev = malloc(sizeof(*dev));
	*dev = (struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1<<20);
	sb = malloc(sizeof(*sb));
	*sb = (struct sb){
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
	};

	if ((errno = -load_sb(sb)))
		goto eek;
	if (!(sb->bitmap = iget(sb, TUX_BITMAP_INO)))
		goto nomem;
	if (!(sb->rootdir = iget(sb, TUX_ROOTDIR_INO)))
		goto nomem;
	if (!(sb->atable = iget(sb, TUX_ATABLE_INO)))
		goto eek;
	if ((errno = -open_inode(sb->bitmap)))
		goto eek;
	if ((errno = -open_inode(sb->rootdir)))
		goto eek;
	if ((errno = -open_inode(sb->atable)))
		goto eek;
	return;
nomem:
	errno = ENOMEM;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	exit(1);
}

/* Stub methods */
static void tux3_destroy(void *userdata)
{
}

static void tux3_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
	fuse_reply_none(req);
}

static void tux3_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
	int to_set, struct fuse_file_info *fi)
{
	fprintf(stderr, "tux3_setattr(%Lx)\n", (L)ino);
	struct inode *inode = open_fuse_ino(ino);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (to_set & FUSE_SET_ATTR_MODE) {
		printf("Setting mode\n");
		inode->i_mode = attr->st_mode;
	}
	if (to_set & FUSE_SET_ATTR_UID) {
		printf("Setting uid\n");
		inode->i_uid = attr->st_uid;
	}
	if (to_set & FUSE_SET_ATTR_GID) {
		printf("Setting gid\n");
		inode->i_gid = attr->st_gid;
	}
	if (to_set & FUSE_SET_ATTR_SIZE) {
		printf("Setting size\n");
		inode->i_size = attr->st_size;
	}
	if (to_set & FUSE_SET_ATTR_ATIME) {
		printf("Setting atime to %Lu\n", (L)attr->st_atime);
		inode->i_atime = attr->st_atim;
	}
	if (to_set & FUSE_SET_ATTR_MTIME) {
		printf("Setting mtime to %Lu\n", (L)attr->st_mtime);
		inode->i_mtime = attr->st_mtim;
	}

	if (save_inode(inode))
		printf("save_inode error\n");

	tuxsync(inode);
	sync_super(sb);

	struct stat stbuf;
	_tux3_getattr(inode, &stbuf);

	dump_attrs(inode);

	if (ino != FUSE_ROOT_ID)
		tuxclose(inode);

	fuse_reply_attr(req, &stbuf, 0.0);
}

static void tux3_readlink(fuse_req_t req, fuse_ino_t ino)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
	mode_t mode, dev_t rdev)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_link(fuse_req_t req, fuse_ino_t ino,
	fuse_ino_t newparent, const char *newname)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_symlink(fuse_req_t req, const char *link,
	fuse_ino_t parent, const char *name)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_rename(fuse_req_t req, fuse_ino_t parent,
	const char *name, fuse_ino_t newparent, const char *newname)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_statfs(fuse_req_t req, fuse_ino_t ino)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	/* Allow all accesses, for now */
	fuse_reply_err(req, 0);
}

static void tux3_fsyncdir(fuse_req_t req, fuse_ino_t ino,
	int datasync, struct fuse_file_info *fi)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (ino != FUSE_ROOT_ID) {
		struct inode *inode = (struct inode *)(unsigned long)fi->fh;
		tuxclose(inode);
	}
	fuse_reply_err(req, 0);
}

static void tux3_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
	struct fuse_file_info *fi)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
	const char *value, size_t size, int flags)
{
	fprintf(stderr, "tux3_setxattr(%Lx, '%s'='%s')\n", (L)ino, name, value);
	struct inode *inode = open_fuse_ino(ino);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	int err = set_xattr(inode, name, strlen(name), value, size, flags);
	if (!err) {
		tuxsync(inode);
		sync_super(sb);
	}
	fuse_reply_err(req, -err);

	if (ino != FUSE_ROOT_ID)
		tuxclose(inode);
}

static void tux3_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t maxsize)
{
	fprintf(stderr, "tux3_getxattr(%Lx, '%s')\n", (L)ino, name);
	struct inode *inode = open_fuse_ino(ino);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
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
	free(data);
out:
	if (ino != FUSE_ROOT_ID)
		tuxclose(inode);
}

static void tux3_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	fprintf(stderr, "tux3_listxattr(%Lx/%zu)\n", (L)ino, size);
	
	struct inode *inode = open_fuse_ino(ino);
	if(!inode) {
		fuse_reply_err(req,ENOENT);
		return;
	}

	char *buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	int len = xattr_list(inode, buf, size);
	fprintf(stderr, "listxattr-buffer:%s\n", buf);
	fuse_reply_buf(req, buf, len);
	free(buf);
	return;
}

static void tux3_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_getlk(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi,
	struct flock *lock)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_setlk(fuse_req_t req, fuse_ino_t ino,
	struct fuse_file_info *fi, struct flock *lock, int sleep)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static void tux3_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize, uint64_t idx)
{
	warn("not implemented");
	fuse_reply_err(req, ENOSYS);
}

static struct fuse_lowlevel_ops tux3_ops = {
	.init = tux3_init,
	.destroy = tux3_destroy,
	.lookup = tux3_lookup,
	.forget = tux3_forget,
	.getattr = tux3_getattr,
	.setattr = tux3_setattr,
	.readlink = tux3_readlink,
	.mknod = tux3_mknod,
	.mkdir = tux3_mkdir,
	.rmdir = tux3_rmdir,
	.link = tux3_link,
	.symlink = tux3_symlink,
	.unlink = tux3_unlink,
	.rename = tux3_rename,
	.create = tux3_create,
	.open = tux3_open,
	.read = tux3_read,
	.write = tux3_write,
	.statfs = tux3_statfs,
	.access = tux3_access,
	.opendir = tux3_opendir,
	.readdir = tux3_readdir,
	.releasedir = tux3_releasedir,
	.fsyncdir = tux3_fsyncdir,
	.flush = tux3_flush,
	.release = tux3_release,
	.fsync = tux3_fsync,
	.setxattr = tux3_setxattr,
	.getxattr = tux3_getxattr,
	.listxattr = tux3_listxattr,
	.removexattr = tux3_removexattr,
	.getlk = tux3_getlk,
	.setlk = tux3_setlk,
	.bmap = tux3_bmap,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc-1, argv+1);

	char *mountpoint;
	int foreground;
	int err = -1;

	if (argc < 3)
		error("usage: %s <volname> <mountpoint>", argv[0]);

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, &foreground) != -1)
	{
		struct fuse_chan *fc = fuse_mount(mountpoint, &args);
		if (fc)
		{
			struct fuse_session *fs = fuse_lowlevel_new(&args,
				&tux3_ops,
				sizeof(tux3_ops),
				argv[1]);

			if (fs)
			{
				if (fuse_set_signal_handlers(fs) != -1)
				{
					fuse_session_add_chan(fs, fc);
					fuse_daemonize(foreground);
					err = fuse_session_loop(fs);
					fuse_remove_signal_handlers(fs);
					fuse_session_remove_chan(fc);
				}

				fuse_session_destroy(fs);
			}

			fuse_unmount(mountpoint, fc);
		}
	}

	fuse_opt_free_args(&args);
	return err ? 1 : 0;
}
