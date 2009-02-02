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

#include "filemap.c"

struct inode *new_inode(struct sb *sb)
{
	struct inode *inode = malloc(sizeof(*inode));
	if (!inode)
		goto error;
	*inode = (struct inode){ INIT_INODE(sb, 0), };
	inode->map = new_map(sb->dev, NULL);
	if (!inode->map)
		goto error_map;
	inode->map->inode = inode;
	return inode;

error_map:
	free(inode);
error:
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

#include "kernel/inode.c"

static void tux_setup_inode(struct inode *inode, dev_t rdev)
{
	inode->i_rdev = rdev;
	if (inode->inum != TUX_VOLMAP_INO)
		inode->map->io = filemap_extent_io;
}

struct inode *iget(struct sb *sb, inum_t inum)
{
	struct inode *inode = new_inode(sb);
	if (inode)
		tux_set_inum(inode, inum);
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
		if (write){
			mark_buffer_dirty(buffer);
			memcpy(bufdata(buffer) + from, data, some);
		}
		else
			memcpy(data, bufdata(buffer) + from, some);
		trace_off("transfer %u bytes, block 0x%Lx, buffer %p", some, (L)bufindex(buffer), buffer);
		//hexdump(bufdata(buffer) + from, some);
		brelse(buffer);
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
	inum_t inum = from_be_u64(entry->inum);
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
	struct inode *inode = tux_new_inode(dir, iattr, 0);
	if (!inode)
		return NULL; // err ???
	int err = make_inode(inode, dir->i_sb->nextalloc);
	if (err)
		goto error; // err ???
	if (tux_create_entry(dir, name, len, tux_inode(inode)->inum, iattr->mode) >= 0)
		return inode;
	purge_inum(tux_sb(dir->i_sb), inode->inum); // test me!!!
error:
	free_inode(inode);
	inode = NULL;
	return NULL; // err ???
}

int tuxunlink(struct inode *dir, const char *name, int len)
{
	struct sb *sb = tux_sb(dir->i_sb);
	struct buffer_head *buffer;
	int err;
	tux_dirent *entry = tux_find_entry(dir, name, len, &buffer);
	if (IS_ERR(entry)) {
		err = PTR_ERR(entry);
		goto error;
	}
	inum_t inum = from_be_u64(entry->inum);
	struct inode *inode = iget(sb, inum);
	if (!inode) {
		err = -ENOMEM;
		goto error_iget;
	}
	if ((err = open_inode(inode)))
		goto error_open;
	err = tree_chop(&inode->btree, &(struct delete_info){ .key = 0 }, -1);
	//inode->i_ctime = dir->i_ctime;
	//inode->i_nlink--;
	free_inode(inode);
	if (err)
		goto error_iget;
	/* FIXME: free btree root */
	if ((err = purge_inum(sb, inum)))
		goto error_iget;
	if ((err = tux_delete_entry(buffer, entry)))
		goto error;
	return 0;

error_open:
	free_inode(inode);
error_iget:
	brelse(buffer);
error:
	return err;
}

int tuxflush(struct inode *inode)
{
	return flush_buffers(mapping(inode));
}

int tuxsync(struct inode *inode)
{
	int err;
	if ((err = tuxflush(inode)))
		return err;
	return save_inode(inode);
}

void tuxclose(struct inode *inode)
{
	tuxsync(inode);
	free_inode(inode);
}

#include "super.c"

#ifdef build_inode
void change_begin(struct sb *sb) { }
void change_end(struct sb *sb) { }

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
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1 << 20, 0);
	struct sb *sb = &(struct sb){
		INIT_SB(dev),
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.volblocks = size >> dev->bits,
	};
	sb->volmap = rapid_open_inode(sb, NULL, 0);
	sb->logmap = rapid_open_inode(sb, NULL, 0);

	trace("make tux3 filesystem on %s (0x%Lx bytes)", name, (L)size);
	if ((errno = -make_tux3(sb)))
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
	flush_buffers(sb->volmap->map);
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
	show_buffers(sb->volmap->map);
	bitmap_dump(sb->bitmap, 0, sb->volblocks);
	show_tree_range(itable_btree(sb), 0, -1);
	exit(0);
eek:
	return error("Eek! %s", strerror(errno));
}
#endif
