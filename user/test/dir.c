/* Lifted from Ext2, blush. GPLv2. Portions (c) Daniel Phillips 2008 */

/*
 *  linux/include/linux/ext2_fs.h
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hexdump.c"
#include "buffer.h"
#include "tux3.h"

#define le16_to_cpu(x) x
#define cpu_to_le16(x) x
#define le32_to_cpu(x) x
#define cpu_to_le32(x) x
#define mark_inode_dirty(x)

typedef u16 le16;

#define EXT2_DIR_PAD 3
#define EXT2_DIR_REC_LEN(name_len) (((name_len) + 8 + EXT2_DIR_PAD) & ~EXT2_DIR_PAD)
#define EXT2_MAX_REC_LEN ((1<<16)-1)
#define EXT2_NAME_LEN 255

typedef struct {
	u32 inode; u16 rec_len; u8 name_len, type;
	char name[EXT2_NAME_LEN];
} ext2_dirent;

static inline unsigned ext2_rec_len_from_disk(le16 dlen)
{
	unsigned len = le16_to_cpu(dlen);
	if (len == EXT2_MAX_REC_LEN)
		return 1 << 16;
	return len;
}

static inline le16 ext2_rec_len_to_disk(unsigned len)
{
	if (len == (1 << 16))
		return cpu_to_le16(EXT2_MAX_REC_LEN);
	else if (len > (1 << 16))
		error("oops");
	return cpu_to_le16(len);
}

static inline int ext2_match(int len, const char *const name, ext2_dirent *de)
{
	if (len != de->name_len)
		return 0;
	if (!de->inode)
		return 0;
	return !memcmp(name, de->name, len);
}

static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
	return (ext2_dirent *)((char *)p + ext2_rec_len_from_disk(p->rec_len));
}

static unsigned blocksize = 4096;

void ext2_dump_entries(struct buffer *buffer)
{
	printf("entries: ");
	ext2_dirent *de = (ext2_dirent *)buffer->data;
	ext2_dirent *lim = buffer->data + blocksize;
	while (de < lim) {
		printf("%.*s (%x:%i) ", de->name_len, de->name, de->inode, de->type);
		de = ext2_next_entry(de);
	}
	printf("\n");
}

ext2_dirent *ext2_find_entry(struct buffer *buffer, char *name, int len)
{
	unsigned reclen = EXT2_DIR_REC_LEN(len);
	ext2_dirent *de = buffer->data;
	ext2_dirent *lim = buffer->data + blocksize - reclen;
	while (de <= lim) {
		if (de->rec_len == 0)
			goto eek;
		if (ext2_match(len, name, de))
			return de;
		de = ext2_next_entry(de);
	}
eek:
	warn("zero-length directory entry");
	brelse(buffer);
	return NULL;
}

enum {
	EXT2_FT_UNKNOWN,
	EXT2_FT_REG,
	EXT2_FT_DIR,
	EXT2_FT_CHR,
	EXT2_FT_BLK,
	EXT2_FT_FIFO,
	EXT2_FT_SOCK,
	EXT2_FT_SYM,
	EXT2_FT_MAX
};

#define STAT_SHIFT 12

static unsigned char ext2_type_by_mode[S_IFMT >> STAT_SHIFT] = {
	[S_IFREG >> STAT_SHIFT]	= EXT2_FT_REG,
	[S_IFDIR >> STAT_SHIFT]	= EXT2_FT_DIR,
	[S_IFCHR >> STAT_SHIFT]	= EXT2_FT_CHR,
	[S_IFBLK >> STAT_SHIFT]	= EXT2_FT_BLK,
	[S_IFIFO >> STAT_SHIFT]	= EXT2_FT_FIFO,
	[S_IFSOCK >> STAT_SHIFT]	= EXT2_FT_SOCK,
	[S_IFLNK >> STAT_SHIFT]	= EXT2_FT_SYM,
};

struct inode { unsigned i_mode; };

static inline void ext2_set_de_type(ext2_dirent *de, unsigned mode)
{
	de->type = ext2_type_by_mode[(mode & S_IFMT) >> STAT_SHIFT];
}

int ext2_create_entry(struct buffer *buffer, char *name, int len, unsigned inum, unsigned mode)
{
	unsigned reclen = EXT2_DIR_REC_LEN(len);
	unsigned short rec_len, name_len;
	int err;
	void *dir_end = buffer->data + blocksize;

	ext2_dirent *de = buffer->data;
	ext2_dirent *lim = buffer->data + blocksize - reclen;
	while (de <= lim) {
		if ((char *)de == dir_end) {
			/* We hit i_size */
			name_len = 0;
			rec_len = blocksize;
			de->rec_len = ext2_rec_len_to_disk(blocksize);
			de->inode = 0;
			goto got_it;
		}
		if (de->rec_len == 0) {
			warn("zero-length directory entry");
			err = -EIO;
			goto out_put;
		}
		name_len = EXT2_DIR_REC_LEN(de->name_len);
		rec_len = ext2_rec_len_from_disk(de->rec_len);
		if (!de->inode && rec_len >= reclen)
			goto got_it;
		if (rec_len >= name_len + reclen)
			goto got_it;
		de = (ext2_dirent *) ((char *)de + rec_len);
	}
	return -EINVAL;
got_it:
	if (de->inode) {
		ext2_dirent *de1 = (ext2_dirent *)((char *)de + name_len);
		de1->rec_len = ext2_rec_len_to_disk(rec_len - name_len);
		de->rec_len = ext2_rec_len_to_disk(name_len);
		de = de1;
	}
	de->name_len = len;
	memcpy(de->name, name, len);
	de->inode = cpu_to_le32(inum);
	ext2_set_de_type(de, mode);
	//dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
out_put:
//	brelse(buffer);
	return err;
}

int ext2_delete_entry(struct buffer *buffer, ext2_dirent *dir)
{
	ext2_dirent *pde = NULL;
	ext2_dirent *de = buffer->data;
	int err;

	while ((char *)de < (char *)dir) {
		if (de->rec_len == 0) {
			warn("zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = de;
		de = ext2_next_entry(de);
	}
	if (pde)
		pde->rec_len = ext2_rec_len_to_disk((void *)dir + ext2_rec_len_from_disk(dir->rec_len) - (void *)pde);
	dir->inode = 0;
//	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
//	mark_inode_dirty(inode);
out:
//	brelse(buffer);
	return err;
}

int main(int argc, char *argv[])
{
	struct dev dev = { .bits = 12 };
	init_buffers(1 << dev.bits, 1 << 20);
	struct buffer *buffer = getblk(&dev, 0);
	blocksize = 1 << dev.bits;
	*(ext2_dirent *)buffer->data = (ext2_dirent){ .rec_len = ext2_rec_len_to_disk(blocksize) };
	ext2_create_entry(buffer, "hello", 5, 0x666, S_IFREG);
	ext2_create_entry(buffer, "world", 5, 0x777, S_IFDIR);
	ext2_dirent *entry = ext2_find_entry(buffer, "world", 5);
	ext2_dump_entries(buffer);
	// hexdump(entry, 16);
	ext2_delete_entry(buffer, entry);
	ext2_dump_entries(buffer);
	return 0;
}
