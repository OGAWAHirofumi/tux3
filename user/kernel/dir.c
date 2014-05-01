/* Lifted from Ext2, blush. GPLv2. Portions (c) Daniel Phillips 2008-2013 */

/*
 * from linux/include/linux/ext2_fs.h and linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 * from linux/include/linux/minix_fs.h
 *
 * Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 * Copied to tux3 and switched back to buffers, Daniel Phillips 2008
 */

#include "tux3.h"
#include "kcompat.h"

#ifndef trace
#define trace trace_off
#endif

#define TUX_DIR_ALIGN		sizeof(inum_t)
#define TUX_DIR_HEAD		(offsetof(tux_dirent, name))
#define TUX_REC_LEN(name_len)	ALIGN((name_len) + TUX_DIR_HEAD, TUX_DIR_ALIGN)
#define TUX_MAX_REC_LEN		((1 << 16) - 1)

static inline unsigned tux_rec_len_from_disk(__be16 dlen)
{
	unsigned len = be16_to_cpu(dlen);

	if (len == TUX_MAX_REC_LEN)
		return 1 << 16;
	return len;
}

static inline __be16 tux_rec_len_to_disk(unsigned len)
{
	assert(len <= (1 << 16));
	if (len == (1 << 16))
		return cpu_to_be16(TUX_MAX_REC_LEN);
	return cpu_to_be16(len);
}

static inline int is_deleted(tux_dirent *entry)
{
	return !entry->name_len; /* ext2 uses !inum for this */
}

static inline int tux_match(tux_dirent *entry, const char *const name,
			    unsigned len)
{
	if (len != entry->name_len)
		return 0;
	if (is_deleted(entry))
		return 0;
	return !memcmp(name, entry->name, len);
}

static inline tux_dirent *next_entry(tux_dirent *entry)
{
	return (void *)entry + tux_rec_len_from_disk(entry->rec_len);
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

#define tux_zero_len_error(dir, block)					\
	tux3_fs_error(tux_sb((dir)->i_sb),				\
		      "zero length entry at inum %Lu, block %Lu",	\
		      tux_inode(dir)->inum, block)

void tux_set_entry(struct buffer_head *buffer, tux_dirent *entry,
		   inum_t inum, umode_t mode)
{
	entry->inum = cpu_to_be64(inum);
	entry->type = tux_type_by_mode[(mode & S_IFMT) >> STAT_SHIFT];
	mark_buffer_dirty_non(buffer);
	blockput(buffer);
}

/*
 * NOTE: For now, we don't have ".." though, we shouldn't use this for
 * "..". rename() shouldn't update ->mtime for ".." usually.
 */
void tux_update_dirent(struct inode *dir, struct buffer_head *buffer,
		       tux_dirent *entry, struct inode *inode)
{
	tux_set_entry(buffer, entry, tux_inode(inode)->inum, inode->i_mode);

	tux3_iattrdirty(dir);
	dir->i_mtime = dir->i_ctime = gettime();
	tux3_mark_inode_dirty(dir);
}

loff_t tux_alloc_entry(struct inode *dir, const char *name, unsigned len,
		       loff_t *size, struct buffer_head **hold)
{
	unsigned delta = tux3_get_current_delta();
	struct sb *sb = tux_sb(dir->i_sb);
	tux_dirent *entry;
	struct buffer_head *buffer, *clone;
	unsigned reclen = TUX_REC_LEN(len), rec_len, offset;
	unsigned uninitialized_var(name_len);
	unsigned blocksize = sb->blocksize;
	block_t block, blocks = *size >> sb->blockbits;
	void *olddata;

	for (block = 0; block < blocks; block++) {
		buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;
		entry = bufdata(buffer);
		tux_dirent *limit = bufdata(buffer) + blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				blockput(buffer);
				tux_zero_len_error(dir, block);
				return -EIO;
			}
			name_len = TUX_REC_LEN(entry->name_len);
			rec_len = tux_rec_len_from_disk(entry->rec_len);
			if (is_deleted(entry) && rec_len >= reclen)
				goto create;
			if (rec_len >= name_len + reclen)
				goto create;
			entry = (void *)entry + rec_len;
		}
		blockput(buffer);
	}
	entry = NULL;
	buffer = blockget(mapping(dir), block);
	assert(!buffer_dirty(buffer));

create:
	/*
	 * The directory is protected by i_mutex.
	 * blockdirty() should never return -EAGAIN.
	 */
	olddata = bufdata(buffer);
	clone = blockdirty(buffer, delta);
	if (IS_ERR(clone)) {
		assert(PTR_ERR(clone) != -EAGAIN);
		blockput(buffer);
		return PTR_ERR(clone);
	}
	if (!entry) {
		/* Expanding the directory size. Initialize block. */
		entry = bufdata(clone);
		memset(entry, 0, blocksize);
		entry->rec_len = tux_rec_len_to_disk(blocksize);
		assert(is_deleted(entry));

		*size += blocksize;
	} else {
		entry = ptr_redirect(entry, olddata, bufdata(clone));

		if (!is_deleted(entry)) {
			tux_dirent *newent = (void *)entry + name_len;
			unsigned rest_rec_len = rec_len - name_len;
			newent->rec_len = tux_rec_len_to_disk(rest_rec_len);
			entry->rec_len = tux_rec_len_to_disk(name_len);
			entry = newent;
		}
	}

	entry->name_len = len;
	memcpy(entry->name, name, len);
	offset = (void *)entry - bufdata(clone);

	*hold = clone;
	return (block << sb->blockbits) + offset; /* only for xattr create */
}

int tux_create_dirent(struct inode *dir, const struct qstr *qstr,
		      struct inode *inode)
{
	struct sb *sb = tux_sb(dir->i_sb);
	inum_t inum = tux_inode(inode)->inum;
	const char *name = (const char *)qstr->name;
	unsigned len = qstr->len;
	struct buffer_head *buffer;
	tux_dirent *entry;
	loff_t i_size, where;
	int err, err2;

	/* Holding dir->i_mutex, so no i_size_read() */
	i_size = dir->i_size;
	where = tux_alloc_entry(dir, name, len, &i_size, &buffer);
	if (where < 0)
		return where;
	entry = bufdata(buffer) + (where & sb->blockmask);

	if (inum == TUX_INVALID_INO) {
		inum_t goal = policy_inum(dir, where, inode);

		err = tux_assign_inum(inode, goal);
		if (err)
			goto error;
		inum = tux_inode(inode)->inum;
		sb->nextinum = inum + 1; /* FIXME: racy */
	}

	/* This releases buffer */
	tux_set_entry(buffer, entry, inum, inode->i_mode);

	tux3_iattrdirty(dir);
	if (dir->i_size != i_size)
		i_size_write(dir, i_size);

	dir->i_mtime = dir->i_ctime = gettime();
	tux3_mark_inode_dirty(dir);

	return 0;

error:
	err2 = tux_delete_entry(dir, buffer, entry);
	if (err2)
		tux3_fs_error(sb, "Failed to recover dir entry (err %d)", err2);

	return err;
}

tux_dirent *tux_find_entry(struct inode *dir, const char *name, unsigned len,
			   struct buffer_head **result, loff_t size)
{
	struct sb *sb = tux_sb(dir->i_sb);
	unsigned reclen = TUX_REC_LEN(len);
	block_t block, blocks = size >> sb->blockbits;
	int err = -ENOENT;

	for (block = 0; block < blocks; block++) {
		struct buffer_head *buffer = blockread(mapping(dir), block);
		if (!buffer) {
			err = -EIO; // need ERR_PTR for blockread!!!
			goto error;
		}
		tux_dirent *entry = bufdata(buffer);
		tux_dirent *limit = (void *)entry + sb->blocksize - reclen;
		while (entry <= limit) {
			if (entry->rec_len == 0) {
				blockput(buffer);
				tux_zero_len_error(dir, block);
				err = -EIO;
				goto error;
			}
			if (tux_match(entry, name, len)) {
				*result = buffer;
				return entry;
			}
			entry = next_entry(entry);
		}
		blockput(buffer);
	}
error:
	*result = NULL;		/* for debug */
	return ERR_PTR(err);
}

tux_dirent *tux_find_dirent(struct inode *dir, const struct qstr *qstr,
			    struct buffer_head **result)
{
	/* Holding dir->i_mutex, so no i_size_read() */
	return tux_find_entry(dir, (const char *)qstr->name, qstr->len,
			      result, dir->i_size);
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

/*
 * Return 0 if the directory entry is OK, and 1 if there is a problem
 */
static int __check_dir_entry(const char *func, int line, struct inode *dir,
			     struct buffer_head *buffer, tux_dirent *entry)
{
	struct sb *sb = tux_sb(dir->i_sb);
	const char *error_msg = NULL;
	const void *base = bufdata(buffer);
	const int off = (void *)entry - base;
	const int rlen = tux_rec_len_from_disk(entry->rec_len);

	if (unlikely(rlen < TUX_REC_LEN(1)))
		error_msg = "rec_len is smaller than minimal";
	else if (unlikely(rlen & (TUX_DIR_ALIGN - 1)))
		error_msg = "rec_len alignment error";
	else if (unlikely(rlen < TUX_REC_LEN(entry->name_len)))
		error_msg = "rec_len is too small for name_len";
	else if (unlikely(off + rlen > sb->blocksize))
		error_msg = "directory entry across range";
	else
		return 0;

	__tux3_err(sb, func, line,
		   "bad entry: %s: inum %Lu, block %Lu, off %d, rec_len %d",
		   error_msg, tux_inode(dir)->inum, bufindex(buffer),
		   off, rlen);

	return 1;
}
#define check_dir_entry(d, b, e)		\
	__check_dir_entry(__func__, __LINE__, d, b, e)

int tux_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	int revalidate = file->f_version != dir->i_version;
	struct sb *sb = tux_sb(dir->i_sb);
	unsigned blockbits = sb->blockbits;
	block_t block, blocks = dir->i_size >> blockbits;
	unsigned offset = ctx->pos & sb->blockmask;

	assert(!(dir->i_size & sb->blockmask));

	/* Clearly invalid offset */
	if (unlikely(offset & (TUX_DIR_ALIGN - 1)))
		return -ENOENT;

	for (block = ctx->pos >> blockbits; block < blocks; block++) {
		struct buffer_head *buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;
		void *base = bufdata(buffer);
		if (revalidate) {
			if (offset) {
				tux_dirent *entry = base + offset;
				tux_dirent *p = base + (offset & sb->blockmask);
				while (p < entry && p->rec_len)
					p = next_entry(p);
				offset = (void *)p - base;
				ctx->pos = (block << blockbits) + offset;
			}
			file->f_version = dir->i_version;
			revalidate = 0;
		}
		tux_dirent *limit = base + sb->blocksize - TUX_REC_LEN(1);
		for (tux_dirent *entry = base + offset; entry <= limit; entry = next_entry(entry)) {
			if (check_dir_entry(dir, buffer, entry)) {
				/* On error, skip to next block */
				ctx->pos = (ctx->pos | (sb->blocksize - 1)) + 1;
				break;
			}
			if (!is_deleted(entry)) {
				unsigned type = (entry->type < TUX_TYPES) ? filetype[entry->type] : DT_UNKNOWN;
				if (!dir_emit(ctx, entry->name, entry->name_len,
					      be64_to_cpu(entry->inum), type)) {
					blockput(buffer);
					return 0;
				}
			}
			ctx->pos += tux_rec_len_from_disk(entry->rec_len);
		}
		blockput(buffer);
		offset = 0;

		if (ctx->pos < dir->i_size) {
			if (!dir_relax(dir))
				return 0;
		}
	}
	return 0;
}

int tux_delete_entry(struct inode *dir, struct buffer_head *buffer,
		     tux_dirent *entry)
{
	unsigned delta = tux3_get_current_delta();
	tux_dirent *prev = NULL, *this = bufdata(buffer);
	struct buffer_head *clone;
	void *olddata;

	while ((char *)this < (char *)entry) {
		if (this->rec_len == 0) {
			blockput(buffer);
			tux_zero_len_error(dir, bufindex(buffer));
			return -EIO;
		}
		prev = this;
		this = next_entry(this);
	}

	/*
	 * The directory is protected by i_mutex.
	 * blockdirty() should never return -EAGAIN.
	 */
	olddata = bufdata(buffer);
	clone = blockdirty(buffer, delta);
	if (IS_ERR(clone)) {
		assert(PTR_ERR(clone) != -EAGAIN);
		blockput(buffer);
		return PTR_ERR(clone);
	}
	entry = ptr_redirect(entry, olddata, bufdata(clone));
	prev = ptr_redirect(prev, olddata, bufdata(clone));

	if (prev)
		prev->rec_len = tux_rec_len_to_disk((void *)next_entry(entry) - (void *)prev);
	memset(entry->name, 0, entry->name_len);
	entry->name_len = entry->type = 0;
	entry->inum = 0;

	mark_buffer_dirty_non(clone);
	blockput(clone);

	return 0;
}

int tux_delete_dirent(struct inode *dir, struct buffer_head *buffer,
		      tux_dirent *entry)
{
	int err;

	err = tux_delete_entry(dir, buffer, entry); /* this releases buffer */
	if (!err) {
		tux3_iattrdirty(dir);
		dir->i_ctime = dir->i_mtime = gettime();
		tux3_mark_inode_dirty(dir);
	}

	return err;
}

int tux_dir_is_empty(struct inode *dir)
{
	struct sb *sb = tux_sb(dir->i_sb);
	block_t block, blocks = dir->i_size >> sb->blockbits;
	__be64 self = cpu_to_be64(tux_inode(dir)->inum);
	struct buffer_head *buffer;

	for (block = 0; block < blocks; block++) {
		buffer = blockread(mapping(dir), block);
		if (!buffer)
			return -EIO;

		tux_dirent *entry = bufdata(buffer);
		tux_dirent *limit = bufdata(buffer) + sb->blocksize - TUX_REC_LEN(1);
		for (; entry <= limit; entry = next_entry(entry)) {
			if (!entry->rec_len) {
				blockput(buffer);
				tux_zero_len_error(dir, block);
				return -EIO;
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
		blockput(buffer);
	}
	return 0;
not_empty:
	blockput(buffer);
	return -ENOTEMPTY;
}
