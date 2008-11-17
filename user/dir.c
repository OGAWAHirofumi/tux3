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
#include "tux3.h"

#define mark_inode_dirty(x)

typedef u16 le16;

#define EXT2_DIR_PAD 3
#define EXT2_REC_LEN(name_len) (((name_len) + 8 + EXT2_DIR_PAD) & ~EXT2_DIR_PAD)
#define EXT2_MAX_REC_LEN ((1<<16)-1)
#define EXT2_NAME_LEN 255

typedef struct { be_u32 inum; be_u16 rec_len; u8 name_len, type; char name[]; } ext2_dirent;

static inline unsigned ext2_rec_len_from_disk(be_u16 dlen)
{
	unsigned len = from_be_u16(dlen);
	if (len == EXT2_MAX_REC_LEN)
		return 1 << 16;
	return len;
}

static inline be_u16 ext2_rec_len_to_disk(unsigned len)
{
	if (len == (1 << 16))
		return to_be_u16(EXT2_MAX_REC_LEN);
	else if (len > (1 << 16))
		error("oops");
	return to_be_u16(len);
}

static inline int is_deleted(ext2_dirent *entry)
{
	return !entry->name_len; /* ext2 uses !inum for this */
}

static inline int ext2_match(ext2_dirent *entry, const char *const name, int len)
{
	if (len != entry->name_len)
		return 0;
	if (is_deleted(entry))
		return 0;
	return !memcmp(name, entry->name, len);
}

static inline ext2_dirent *next_entry(ext2_dirent *entry)
{
	return (ext2_dirent *)((char *)entry + ext2_rec_len_from_disk(entry->rec_len));
}

enum {
	EXT2_UNKNOWN,
	EXT2_REG,
	EXT2_DIR,
	EXT2_CHR,
	EXT2_BLK,
	EXT2_FIFO,
	EXT2_SOCK,
	EXT2_LNK,
	EXT2_TYPES
};

#define STAT_SHIFT 12

static unsigned char ext2_type_by_mode[S_IFMT >> STAT_SHIFT] = {
	[S_IFREG >> STAT_SHIFT] = EXT2_REG,
	[S_IFDIR >> STAT_SHIFT] = EXT2_DIR,
	[S_IFCHR >> STAT_SHIFT] = EXT2_CHR,
	[S_IFBLK >> STAT_SHIFT] = EXT2_BLK,
	[S_IFIFO >> STAT_SHIFT] = EXT2_FIFO,
	[S_IFSOCK >> STAT_SHIFT] = EXT2_SOCK,
	[S_IFLNK >> STAT_SHIFT] = EXT2_LNK,
};

void ext2_dump_entries(struct buffer *buffer)
{
	unsigned blocksize = 1 << buffer->map->inode->i_sb->blockbits;
	printf("entries <%Lx:%Lx>: ", (L)buffer->map->inode->inum, (L)buffer->index);
	ext2_dirent *entry = (ext2_dirent *)buffer->data;
	ext2_dirent *limit = buffer->data + blocksize;
	while (entry < limit) {
		if (!entry->rec_len) {
			warn("Zero length entry");
			break;
		}
		if (!is_deleted(entry))
			printf("%.*s (%x:%i) ",
				entry->name_len,
				entry->name,
				entry->inum,
				entry->type);
		entry = next_entry(entry);
	}
	brelse(buffer);
	printf("\n");
}

loff_t ext2_create_entry(struct inode *dir, const char *name, int len, unsigned inum, unsigned mode)
{
	ext2_dirent *entry;
	struct buffer *buffer;
	unsigned reclen = EXT2_REC_LEN(len), rec_len, name_len, offset;
	unsigned blockbits = dir->i_sb->blockbits, blocksize = 1 << blockbits;
	unsigned blocks = dir->i_size >> blockbits, block;
	for (block = 0; block < blocks; block++) {
		buffer = blockget(mapping(dir), block);
		entry = buffer->data;
		ext2_dirent *limit = buffer->data + blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				warn("zero-length directory entry");
				brelse(buffer);
				return -1;
			}
			name_len = EXT2_REC_LEN(entry->name_len);
			rec_len = ext2_rec_len_from_disk(entry->rec_len);
			if (is_deleted(entry) && rec_len >= reclen)
				goto create;
			if (rec_len >= name_len + reclen)
				goto create;
			entry = (ext2_dirent *)((char *)entry + rec_len);
		}
		brelse(buffer);
	}
	buffer = blockget(mapping(dir), block = blocks);
	entry = buffer->data;
	name_len = 0;
	rec_len = blocksize;
	*entry = (ext2_dirent){ .rec_len = ext2_rec_len_to_disk(blocksize) };
	dir->i_size += blocksize;
create:
	if (!is_deleted(entry)) {
		ext2_dirent *newent = (ext2_dirent *)((char *)entry + name_len);
		newent->rec_len = ext2_rec_len_to_disk(rec_len - name_len);
		entry->rec_len = ext2_rec_len_to_disk(name_len);
		entry = newent;
	}
	entry->name_len = len;
	memcpy(entry->name, name, len);
	entry->inum = to_be_u32(inum);
	entry->type = ext2_type_by_mode[(mode & S_IFMT) >> STAT_SHIFT];
	dir->i_mtime = dir->i_ctime = tuxtime();
	mark_inode_dirty(dir);
	offset = (void *)entry - buffer->data;
	brelse_dirty(buffer);
	return (block << blockbits) + offset;
}

ext2_dirent *ext2_find_entry(struct inode *dir, const char *name, int len, struct buffer **result)
{
	unsigned reclen = EXT2_REC_LEN(len);
	unsigned blocksize = 1 << dir->i_sb->blockbits;
	unsigned blocks = dir->i_size >> dir->i_sb->blockbits, block;
	for (block = 0; block < blocks; block++) {
		struct buffer *buffer = blockread(mapping(dir), block);
		ext2_dirent *entry = buffer->data;
		ext2_dirent *limit = (void *)entry + blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				brelse(buffer);
				warn("zero length entry at <%Lx:%x>", (L)dir->inum, block);
				return NULL;
			}
			if (ext2_match(entry, name, len)) {
				*result = buffer;
				return entry;
			}
			entry = next_entry(entry);
		}
		brelse(buffer);
	}
	*result = NULL;
	return NULL;
}

enum {DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK };

static unsigned char filetype[EXT2_TYPES] = {
	[EXT2_UNKNOWN] = DT_UNKNOWN,
	[EXT2_REG] = DT_REG,
	[EXT2_DIR] = DT_DIR,
	[EXT2_CHR] = DT_CHR,
	[EXT2_BLK] = DT_BLK,
	[EXT2_FIFO] = DT_FIFO,
	[EXT2_SOCK] = DT_SOCK,
	[EXT2_LNK] = DT_LNK,
};

typedef int (filldir_t)(void *dirent, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type);

static int ext2_readdir(struct file *file, void *state, filldir_t filldir)
{
	loff_t pos = file->f_pos;
	struct inode *dir = file->f_inode;
	int revalidate = file->f_version != dir->i_version;
	unsigned blockbits = dir->i_sb->blockbits;
	unsigned blocksize = 1 << blockbits;
	unsigned blockmask = blocksize - 1;
	unsigned blocks = dir->i_size >> blockbits;
	unsigned offset = pos & blockmask;
	for (unsigned block = pos >> blockbits ; block < blocks; block++) {
		struct buffer *buffer = blockread(mapping(dir), block);
		void *base = buffer->data;
		if (!buffer)
			return -EIO;
		if (revalidate) {
			if (offset) {
				ext2_dirent *entry = base + offset;
				ext2_dirent *p = base + (offset & blockmask);
				while (p < entry && p->rec_len)
					p = next_entry(p);
				offset = (void *)p - base;
				file->f_pos = (block << blockbits) + offset;
			}
			file->f_version = dir->i_version;
			revalidate = 0;
		}
		unsigned size = dir->i_size - (block << blockbits);
		ext2_dirent *limit = base + (size > blocksize ? blocksize : size) - EXT2_REC_LEN(1);
		for (ext2_dirent *entry = base + offset; entry <= limit; entry = next_entry(entry)) {
			if (entry->rec_len == 0) {
				brelse(buffer);
				warn("zero length entry at <%Lx:%x>", (L)dir->inum, block);
				return -EIO;
			}
			if (!is_deleted(entry)) {
				unsigned type = (entry->type < EXT2_TYPES) ? filetype[entry->type] : DT_UNKNOWN;
				int lame = filldir(
					state, entry->name, entry->name_len,
					(block << blockbits) | ((void *)entry - base),
					from_be_u32(entry->inum), type);
				if (lame) {
					brelse(buffer);
					return 0;
				}
			}
			file->f_pos += ext2_rec_len_from_disk(entry->rec_len);
		}
		brelse(buffer);
		offset = 0;
	}
	return 0;
}

int ext2_delete_entry(struct buffer *buffer, ext2_dirent *entry)
{
	ext2_dirent *prev = NULL, *this = buffer->data;
	while ((char *)this < (char *)entry) {
		if (this->rec_len == 0) {
			warn("zero-length directory entry");
			brelse(buffer);
			return -EIO;
		}
		prev = this;
		this = next_entry(this);
	}
	if (prev)
		prev->rec_len = ext2_rec_len_to_disk((void *)entry +
		ext2_rec_len_from_disk(entry->rec_len) - (void *)prev);
	memset(entry->name, 0, entry->name_len);
	entry->name_len = entry->type = 0;
	entry->inum = to_be_u32(0);
	brelse(buffer);
	return 0;
}

int filldir(void *entry, char *name, unsigned namelen, loff_t offset, unsigned inum, unsigned type)
{
	printf("\"%.*s\"\n", namelen, name);
	return 0;
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	map_t *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	struct buffer *buffer;
	struct sb *sb = &(struct sb){ .super = { .volblocks = to_be_u64(150) }, .blockbits = dev->bits };
	map->inode = &(struct inode){ .i_sb = sb, .map = map, .i_mode = S_IFDIR };
	ext2_create_entry(map->inode, "hello", 5, 0x666, S_IFREG);
	ext2_create_entry(map->inode, "world", 5, 0x777, S_IFLNK);
	ext2_dirent *entry = ext2_find_entry(map->inode, "hello", 5, &buffer);
	if (entry)
		hexdump(entry, entry->name_len);
	ext2_dump_entries(blockget(map, 0));

	if (!ext2_delete_entry(buffer, entry)) {
		show_buffers(map);
		map->inode->i_ctime = map->inode->i_mtime = tuxtime();
		mark_inode_dirty(map->inode);
	}

	ext2_dump_entries(blockget(map, 0));
	struct file *file = &(struct file){ .f_inode = map->inode };
	for (int i = 0; i < 10; i++) {
		char name[100];
		sprintf(name, "file%i", i);
		ext2_create_entry(map->inode, name, strlen(name), 0x800 + i, S_IFREG);
	}
	ext2_dump_entries(blockget(map, 0));
	char dents[10000];
	ext2_readdir(file, dents, filldir);
	show_buffers(map);
	return 0;
}
