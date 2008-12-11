/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

#define filemap_included
#include "filemap.c"
#undef main

struct inode *new_inode(struct sb *sb)
{
	map_t *map = new_map(sb->devmap->dev, &filemap_ops);
	if (!map)
		goto eek;
	struct inode *inode = malloc(sizeof(*inode));
	if (!inode)
		goto eek;
	*inode = (struct inode){ .i_sb = sb, .map = map, .i_version = 1, .i_nlink = 1, };
	return inode->map->inode = inode;
eek:
	if (map)
		free_map(map);
	return NULL;
}

void free_inode(struct inode *inode)
{
	assert(mapping(inode)); /* some inodes are not malloced */
	free_map(mapping(inode)); // invalidate dirty buffers!!!
	if (inode->xcache)
		free(inode->xcache);
	free(inode);
}

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/inode.c"

struct inode *iget(struct sb *sb, inum_t inum)
{
	struct inode *inode = new_inode(sb);
	if (inode)
		inode->inum = inum;
	return inode;
}

int tuxio(struct file *file, char *data, unsigned len, int write)
{
	int err = 0;
	struct inode *inode = file->f_inode;
	loff_t pos = file->f_pos;
	trace("%s %u bytes at %Lu, isize = 0x%Lx", write ? "write" : "read", len, (L)pos, (L)inode->i_size);
	if (write && pos + len > MAX_FILESIZE)
		return -EFBIG;
	if (!write && pos + len > inode->i_size) {
		if (pos >= inode->i_size)
			return 0;
		len = inode->i_size - pos;
	}
	unsigned bbits = tux_sb(inode->i_sb)->blockbits;
	unsigned bsize = tux_sb(inode->i_sb)->blocksize;
	unsigned bmask = tux_sb(inode->i_sb)->blockmask;
	loff_t tail = len;
	while (tail) {
		unsigned from = pos & bmask;
		unsigned some = from + tail > bsize ? bsize - from : tail;
		int full = write && some == bsize;
		struct buffer_head *buffer = (full ? blockget : blockread)(mapping(inode), pos >> bbits);
		if (!buffer) {
			err = -EIO;
			break;
		}
		if (write)
			memcpy(bufdata(buffer) + from, data, some);
		else
			memcpy(data, bufdata(buffer) + from, some);
		printf("transfer %u bytes, block 0x%Lx, buffer %p\n", some, (L)bufindex(buffer), buffer);
		hexdump(bufdata(buffer) + from, some);
		brelse_dirty(buffer);
		tail -= some;
		data += some;
		pos += some;
	}
	file->f_pos = pos;
	if (write && inode->i_size < pos)
		inode->i_size = pos;
	return err ? err : len - tail;
}

int tuxread(struct file *file, char *data, unsigned len)
{
	return tuxio(file, data, len, 0);
}

int tuxwrite(struct file *file, const char *data, unsigned len)
{
	return tuxio(file, (void *)data, len, 1);
}

void tuxseek(struct file *file, loff_t pos)
{
	warn("seek to 0x%Lx", (L)pos);
	file->f_pos = pos;
}

struct inode *tuxopen(struct inode *dir, const char *name, int len)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_entry(dir, name, len, &buffer);
	if (IS_ERR(entry))
		return NULL; // ERR_PTR me!!!
	inum_t inum = from_be_u32(entry->inum);
	brelse(buffer);
	struct inode *inode = iget(dir->i_sb, inum);
	return open_inode(inode) ? NULL : inode;
}

struct inode *tuxcreate(struct inode *dir, const char *name, int len, struct tux_iattr *iattr)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_entry(dir, name, len, &buffer);
	if (!IS_ERR(entry)) {
		brelse(buffer);
		return NULL; // should allow create of a file that already exists!!!
	}
	if (PTR_ERR(entry) != -ENOENT)
		return NULL;

	/*
	 * For now the inum allocation goal is the same as the block allocation
	 * goal.  This allows a maximum inum density of one per block and should
	 * give pretty good spacial correlation between inode table blocks and
	 * file data belonging to those inodes provided somebody sets the block
	 * allocation goal based on the directory the file will be in.
	 */
	struct inode *inode = new_inode(dir->i_sb);
	if (!inode)
		return NULL; // err ???
	iattr->mtime = iattr->ctime = iattr->atime = gettime();
	int err = make_inode(inode, dir->i_sb->nextalloc, iattr);
	if (err)
		goto error; // err ???
	if (tux_create_entry(dir, name, len, tux_inode(inode)->inum, iattr->mode) >= 0)
		return inode;
	purge_inum(&tux_sb(dir->i_sb)->itable, inode->inum); // test me!!!
error:
	free_inode(inode);
	inode = NULL;
	return NULL; // err ???
}

int tuxflush(struct inode *inode)
{
	return flush_buffers(mapping(inode));
}

int tuxsync(struct inode *inode)
{
	tuxflush(inode);
	save_inode(inode);
	return 0; // wrong!!!
}

void tuxclose(struct inode *inode)
{
	tuxsync(inode);
	free_inode(inode);
}

#include "super.c"

#ifndef include_inode_c
int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	int err = 0;
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	init_buffers(dev, 1 << 20);
	struct sb *sb = &(struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = size >> dev->bits,
	};

	trace("make tux3 filesystem on %s (0x%Lx bytes)", name, (L)size);
	if ((errno = -make_tux3(sb, fd)))
		goto eek;
	trace("create file");
	struct inode *inode = tuxcreate(sb->rootdir, "foo", 3, &(struct tux_iattr){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		exit(1);
	tux_dump_entries(blockget(mapping(sb->rootdir), 0));

	trace(">>> write file");
	char buf[100] = { };
	struct file *file = &(struct file){ .f_inode = inode };
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	err = tuxwrite(file, "hello ", 6);
	err = tuxwrite(file, "world!", 6);
#if 0
	tuxflush(sb->bitmap);
	flush_buffers(sb->devmap);
#endif
#if 1
	trace(">>> close file <<<");
	set_xattr(inode, "foo", 5, "hello world!", 12, 0);
	save_inode(inode);
	tuxclose(inode);
	trace(">>> open file");
	file = &(struct file){ .f_inode = tuxopen(sb->rootdir, "foo", 3) };
	inode = file->f_inode;
	xcache_dump(inode);
#endif
	trace(">>> read file");
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	memset(buf, 0, sizeof(buf));
	int got = tuxread(file, buf, sizeof(buf));
	trace_off("got %x bytes", got);
	if (got < 0)
		exit(1);
	hexdump(buf, got);
	trace(">>> show state");
	show_buffers(mapping(file->f_inode));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->devmap);
	bitmap_dump(sb->bitmap, 0, sb->volblocks);
	show_tree_range(&sb->itable, 0, -1);
	exit(0);
eek:
	return error("Eek! %s", strerror(errno));
}
#endif
