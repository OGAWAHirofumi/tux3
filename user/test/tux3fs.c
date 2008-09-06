/*
 * FUSE-Tux3: Mount tux3 in userspace.
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
 * Compile: gcc -std=gnu99 buffer.c diskio.c fuse-tux3.c \
 *              -D_FILE_OFFSET_BITS=64 -lfuse -o fuse-tux3
 * (-D_FILE_OFFSET_BITS=64 might be only on 64 bit platforms, not sure.)
 * Run:
 * 0. sudo mknod -m 666 /dev/fuse c 10 229
 *    Install libfuse and headers: sudo apt-get install libfuse-dev
 *    Install fuse-utils: sudo apt-get install fuse-utils
 *    build fuse kernel module: cd linux && make ;-)
 *    insert fuse kernel module: sudo insmod fs/fuse/fuse.ko
 * 1. Create a tux3 fs on __fuse__tux3fs using some combination of dd
 *    and ./tux3 make __fuse__tux3fs.
 * 2. Mount on foo/ like: ./tux3fuse -f foo/     (-f for foreground)
 */

#define FUSE_USE_VERSION 25

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include "trace.h"
#include "tux3.h"
#include "buffer.h"
#include "diskio.h"

#define include_inode_c
#include "inode.c"

static fd_t fd;
static u64 volsize;
static const char *volname = "__fuse__tux3fs";
static struct sb *sb;
static struct dev *dev;

static int tux3_open(const char *path, struct fuse_file_info *fi)
{
	printf("---- open file ----\n");
	printf("flags: %i\n", fi->flags);
	fi->flags |= 0666;
	return 0;
}

static int tux3_read(const char *path, char *buf, 
	size_t size, off_t offset, struct fuse_file_info *fi)
{
	printf("---- read file ----\n");
	const char *filename = path;
	struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
	struct file *file = &(struct file){ .f_inode = inode };
	printf("userspace tries to seek to %Li\n", (L)offset);
	if (offset >= inode->i_size)
	{
		printf("EOF!\n");
		errno = EOF;
		return 0;
	}
	tuxseek(file, offset);
	int read = tuxread(file, buf, size);
	if (read < 0)
	{
		errno = -read;
		goto eek;
	}
	if (offset + read > inode->i_size)
		return -EOF;
	return read;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	return -errno;
}

static int tux3_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	const char *filename = path;
	struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
	if (!inode) {
		printf("---- create file ----\n");
		inode = tuxcreate(sb->rootdir, filename, strlen(filename),
			&(struct iattr){ .mode = S_IFREG | 0666 });
		if (!inode) return -1;
	}
	return 0;
}

static int tux3_write(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	warn("---- write file ----");
	const char *filename = path;
	struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
	if (!inode) {
		printf("---- create file ----\n");
		inode = tuxcreate(sb->rootdir, filename, strlen(filename),
			&(struct iattr){ .mode = S_IFREG | S_IRWXU });
	}
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
	return written;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	return -errno;
}

struct fillstate { char *dirent; int done; };

int tux3_filldir(void *info, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type)
{
	struct fillstate *state = info;
	if (state->done || namelen > EXT2_NAME_LEN)
		return -EINVAL;
	printf("'%.*s'\n", namelen, name);
	memcpy(state->dirent, name, namelen);
	(state->dirent)[namelen] = 0;
	state->done = 1;
	return 0;
}

static int tux3_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	printf("--- readdir --- '%s' at %Lx\n", path, (L)offset);
	struct file *dirfile = &(struct file){ .f_inode = sb->rootdir, .f_pos = offset };
	//filler(buf, ".", NULL, 0);
	//filler(buf, "..", NULL, 0);
	char dirent[EXT2_NAME_LEN + 1];
	while (dirfile->f_pos < dirfile->f_inode->i_size) {
		if ((errno = -ext2_readdir(dirfile, &(struct fillstate){ .dirent = dirent }, tux3_filldir)))
			return -errno;
		//warn(">>> pos = %Lx", (L)dirfile->f_pos);
		if (filler(buf, dirent, NULL, dirfile->f_pos)) {
			warn("fuse buffer full");
			return 0;
		}
	}
	return 0;
}

static int tux3_getattr(const char *path, struct stat *stbuf)
{
	printf("---- get attr for '%s' ----\n", path);
	// this is probably mostly wrong as well
	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0)
	{
		stbuf->st_mode = sb->rootdir->i_mode;
		stbuf->st_nlink = 2;
		return 0;
	}
	const char *filename = path;
	struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
	if (!inode)
		return -ENOENT;
	stbuf->st_mode  = inode->i_mode;
	stbuf->st_atime = inode->i_atime;
	stbuf->st_mtime = inode->i_mtime;
	stbuf->st_ctime = inode->i_ctime;
	stbuf->st_size  = inode->i_size;
	stbuf->st_uid   = inode->i_uid;
	stbuf->st_gid   = inode->i_gid;
	stbuf->st_nlink = inode->i_links;
	return 0;
}

static int tux3_unlink(const char *path)
{
	printf("---- delete file ----\n");
	struct buffer *buffer;
	const char *filename = path;
	ext2_dirent *entry = ext2_find_entry(sb->rootdir, filename, strlen(filename), &buffer);
	if (!entry) {
		errno = ENOENT;
		goto eek;
	}
	struct inode *inode = mapped_inode(sb, entry->inum, NULL);
	if ((errno = -open_inode(inode)))
		goto eek;
	if ((errno = -tree_chop(&inode->btree, &(struct delete_info){ .key = 0 }, -1)))
		goto eek;
	if ((errno = -ext2_delete_entry(buffer, entry)))
		goto eek;
	free_inode(inode);
	return 0;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	return -errno;
}

static struct fuse_operations tux3_oper = {
	.read = tux3_read,
	.open = tux3_open,
	.write = tux3_write,
	.readdir = tux3_readdir,
	.getattr = tux3_getattr,
	.unlink = tux3_unlink,
	.create = tux3_create,
};

int main(int argc, char **argv)
{
	fd = open(volname, O_RDWR, S_IRWXU);
	volsize = 0;
	if (fdsize64(fd, &volsize))
		error("fdsize64 failed for '%s' (%s)", volname, strerror(errno));
	dev = &(struct dev){ fd, .bits = 12 };
	init_buffers(dev, 1<<20);
	sb = &(struct sb){ };
	*sb = (struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = volsize >> dev->bits,
		.freeblocks = volsize >> dev->bits,
		.itree = (struct btree){ .sb = sb, .ops = &itree_ops,
			.entries_per_leaf = 1 << (dev->bits - 6) } };

	sb->bitmap = new_inode(sb, 0);
	if (!sb->bitmap)
		goto eek;
	if ((errno = -load_sb(sb)))
		goto eek;
	if (!(sb->rootdir = new_inode(sb, 0xd)))
		goto eek;
	if ((errno = -open_inode(sb->rootdir)))
		goto eek;
	if ((errno = -open_inode(sb->bitmap)))
		goto eek;
	return fuse_main(argc, argv, &tux3_oper, NULL);

eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	return 1;
}
