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

#include "tux3.h"

#define TUX_DIR_PAD 3
#define TUX_REC_LEN(name_len) (((name_len) + 8 + TUX_DIR_PAD) & ~TUX_DIR_PAD)
#define TUX_MAX_REC_LEN ((1<<16)-1)

static inline unsigned tux_rec_len_from_disk(be_u16 dlen)
{
	unsigned len = from_be_u16(dlen);
	if (len == TUX_MAX_REC_LEN)
		return 1 << 16;
	return len;
}

static inline be_u16 tux_rec_len_to_disk(unsigned len)
{
	if (len == (1 << 16))
		return to_be_u16(TUX_MAX_REC_LEN);
	else if (len > (1 << 16))
		error("oops");
	return to_be_u16(len);
}

static inline int is_deleted(tux_dirent *entry)
{
	return !entry->name_len; /* ext2 uses !inum for this */
}

static inline int tux_match(tux_dirent *entry, const char *const name, int len)
{
	if (len != entry->name_len)
		return 0;
	if (is_deleted(entry))
		return 0;
	return !memcmp(name, entry->name, len);
}

static inline tux_dirent *next_entry(tux_dirent *entry)
{
	return (tux_dirent *)((char *)entry + tux_rec_len_from_disk(entry->rec_len));
}

enum {
	TUX_UNKNOWN,
	TUX_REG,
	TUX_DIR,
	TUX_CHR,
	TUX_BLK,
	TUX_FIFO,
	TUX_SOCK,
	TUX_LNK,
	TUX_TYPES
};

#define STAT_SHIFT 12

static unsigned char tux_type_by_mode[S_IFMT >> STAT_SHIFT] = {
	[S_IFREG >> STAT_SHIFT] = TUX_REG,
	[S_IFDIR >> STAT_SHIFT] = TUX_DIR,
	[S_IFCHR >> STAT_SHIFT] = TUX_CHR,
	[S_IFBLK >> STAT_SHIFT] = TUX_BLK,
	[S_IFIFO >> STAT_SHIFT] = TUX_FIFO,
	[S_IFSOCK >> STAT_SHIFT] = TUX_SOCK,
	[S_IFLNK >> STAT_SHIFT] = TUX_LNK,
};

loff_t tux_create_entry(struct inode *dir, const char *name, int len, inum_t inum, unsigned mode)
{
	tux_dirent *entry;
	struct buffer_head *buffer;
	unsigned reclen = TUX_REC_LEN(len), rec_len, name_len, offset;
	unsigned blockbits = tux_sb(dir->i_sb)->blockbits, blocksize = 1 << blockbits;
	unsigned blocks = dir->i_size >> blockbits, block;
	for (block = 0; block < blocks; block++) {
		buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;
		entry = bufdata(buffer);
		tux_dirent *limit = bufdata(buffer) + blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				warn("zero-length directory entry");
				brelse(buffer);
				return -EIO;
			}
			name_len = TUX_REC_LEN(entry->name_len);
			rec_len = tux_rec_len_from_disk(entry->rec_len);
			if (is_deleted(entry) && rec_len >= reclen)
				goto create;
			if (rec_len >= name_len + reclen)
				goto create;
			entry = (tux_dirent *)((char *)entry + rec_len);
		}
		brelse(buffer);
	}
	buffer = blockget(mapping(dir), block = blocks);
	entry = bufdata(buffer);
	name_len = 0;
	rec_len = blocksize;
	*entry = (tux_dirent){ .rec_len = tux_rec_len_to_disk(blocksize) };
	dir->i_size += blocksize;
create:
	if (!is_deleted(entry)) {
		tux_dirent *newent = (tux_dirent *)((char *)entry + name_len);
		newent->rec_len = tux_rec_len_to_disk(rec_len - name_len);
		entry->rec_len = tux_rec_len_to_disk(name_len);
		entry = newent;
	}
	entry->name_len = len;
	memcpy(entry->name, name, len);
	entry->inum = to_be_u32(inum);
	entry->type = tux_type_by_mode[(mode & S_IFMT) >> STAT_SHIFT];
	dir->i_mtime = dir->i_ctime = gettime();
	mark_inode_dirty(dir);
	offset = (void *)entry - bufdata(buffer);
	brelse_dirty(buffer);
	return (block << blockbits) + offset; /* only needed for xattr create */
}

tux_dirent *tux_find_entry(struct inode *dir, const char *name, int len, struct buffer_head **result)
{
	unsigned reclen = TUX_REC_LEN(len);
	unsigned blocksize = 1 << tux_sb(dir->i_sb)->blockbits;
	unsigned blocks = dir->i_size >> tux_sb(dir->i_sb)->blockbits, block;
	for (block = 0; block < blocks; block++) {
		struct buffer_head *buffer = blockread(mapping(dir), block);
		if (!buffer)
			break; // need ERR_PTR for blockread!!!
		tux_dirent *entry = bufdata(buffer);
		tux_dirent *limit = (void *)entry + blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				brelse(buffer);
				warn("zero length entry at <%Lx:%x>", (L)tux_inode(dir)->inum, block);
				return ERR_PTR(-EIO);
			}
			if (tux_match(entry, name, len)) {
				*result = buffer;
				return entry;
			}
			entry = next_entry(entry);
		}
		brelse(buffer);
	}
	*result = NULL;
	return ERR_PTR(-ENOENT);
}

static unsigned char filetype[TUX_TYPES] = {
	[TUX_UNKNOWN] = DT_UNKNOWN,
	[TUX_REG] = DT_REG,
	[TUX_DIR] = DT_DIR,
	[TUX_CHR] = DT_CHR,
	[TUX_BLK] = DT_BLK,
	[TUX_FIFO] = DT_FIFO,
	[TUX_SOCK] = DT_SOCK,
	[TUX_LNK] = DT_LNK,
};

int tux_readdir(struct file *file, void *state, filldir_t filldir)
{
	loff_t pos = file->f_pos;
#ifdef __KERNEL__
	struct inode *dir = file->f_dentry->d_inode;
#else
	struct inode *dir = file->f_inode;
#endif
	int revalidate = file->f_version != dir->i_version;
	unsigned blockbits = tux_sb(dir->i_sb)->blockbits;
	unsigned blocksize = 1 << blockbits;
	unsigned blockmask = blocksize - 1;
	unsigned blocks = dir->i_size >> blockbits;
	unsigned offset = pos & blockmask;
	for (unsigned block = pos >> blockbits ; block < blocks; block++) {
		struct buffer_head *buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;
		void *base = bufdata(buffer);
		if (revalidate) {
			if (offset) {
				tux_dirent *entry = base + offset;
				tux_dirent *p = base + (offset & blockmask);
				while (p < entry && p->rec_len)
					p = next_entry(p);
				offset = (void *)p - base;
				file->f_pos = (block << blockbits) + offset;
			}
			file->f_version = dir->i_version;
			revalidate = 0;
		}
		unsigned size = dir->i_size - (block << blockbits);
		tux_dirent *limit = base + (size > blocksize ? blocksize : size) - TUX_REC_LEN(1);
		for (tux_dirent *entry = base + offset; entry <= limit; entry = next_entry(entry)) {
			if (entry->rec_len == 0) {
				brelse(buffer);
				warn("zero length entry at <%Lx:%x>", (L)tux_inode(dir)->inum, block);
				return -EIO;
			}
			if (!is_deleted(entry)) {
				unsigned type = (entry->type < TUX_TYPES) ? filetype[entry->type] : DT_UNKNOWN;
				int lame = filldir(
					state, entry->name, entry->name_len,
					(block << blockbits) | ((void *)entry - base),
					from_be_u32(entry->inum), type);
				if (lame) {
					brelse(buffer);
					return 0;
				}
			}
			file->f_pos += tux_rec_len_from_disk(entry->rec_len);
		}
		brelse(buffer);
		offset = 0;
	}
	return 0;
}

int tux_delete_entry(struct buffer_head *buffer, tux_dirent *entry)
{
	struct inode *dir = buffer_inode(buffer);
	tux_dirent *prev = NULL, *this = bufdata(buffer);
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
		prev->rec_len = tux_rec_len_to_disk((void *)entry +
		tux_rec_len_from_disk(entry->rec_len) - (void *)prev);
	memset(entry->name, 0, entry->name_len);
	entry->name_len = entry->type = 0;
	entry->inum = to_be_u32(0);
	brelse_dirty(buffer);
	dir->i_ctime = dir->i_mtime = gettime();
	mark_inode_dirty(dir);
	return 0;
}

int tux_dir_is_empty(struct inode *dir)
{
	unsigned blockbits = tux_sb(dir->i_sb)->blockbits;
	unsigned blocks = dir->i_size >> blockbits, blocksize = 1 << blockbits;
	/* FIXME: will overflow on 32bit arch */
	be_u32 self = to_be_u32(tux_inode(dir)->inum);
	struct buffer_head *buffer;

	for (unsigned block = 0; block < blocks; block++) {
		buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;

		tux_dirent *entry = bufdata(buffer);
		tux_dirent *limit = bufdata(buffer) + blocksize - TUX_REC_LEN(1);
		for (; entry <= limit; entry = next_entry(entry)) {
			if (!entry->rec_len) {
				warn("zero length entry at <%Lx:%x>", (L)tux_inode(dir)->inum, block);
				goto not_empty;
			}
			if (is_deleted(entry))
				continue;
			if (entry->name[0] != '.')
				goto not_empty;
			if (entry->name_len > 2)
				goto not_empty;
			if (entry->name_len < 2) {
				if (entry->inum != self)
					goto not_empty;
			} else if (entry->name[1] != '.')
				goto not_empty;
		}
		brelse(buffer);
	}
	return 1;
not_empty:
	brelse(buffer);
	return 0;
}
