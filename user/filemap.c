#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

#include "kernel/filemap.c"

static int filemap_bufvec_check(struct bufvec *bufvec, enum map_mode mode)
{
	struct buffer_head *buffer;

	trace("%s inode 0x%Lx block 0x%Lx",
	      (mode == MAP_READ) ? "read" :
			(mode == MAP_WRITE) ? "write" : "redirect",
	      buffer_inode(bufvec_contig_buf(bufvec))->inum,
	      bufvec_contig_index(bufvec));

	if (bufvec_contig_last_index(bufvec) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;

	list_for_each_entry(buffer, &bufvec->contig, link) {
		if (mode != MAP_READ && buffer_empty(buffer))
			warn("egad, writing an invalid buffer");
		if (mode == MAP_READ && buffer_dirty(buffer))
			warn("egad, reading a dirty buffer");
	}

	return 0;
}

/*
 * Extrapolate from single buffer blockread to opportunistic extent IO
 *
 * Essentially readahead:
 *  - stop at first present buffer
 *  - stop at end of file
 *
 * Stop when extent is "big enough", whatever that means.
 */
static int guess_readahead(struct bufvec *bufvec, struct inode *inode,
			   block_t index)
{
	struct sb *sb = inode->i_sb;
	struct buffer_head *buffer;
	block_t limit;
	int ret;

	bufvec_init(bufvec, NULL);

	limit = (inode->i_size + sb->blockmask) >> sb->blockbits;
	/* FIXME: MAX_EXTENT is not true for dleaf2 */
	if (limit > index + MAX_EXTENT)
		limit = index + MAX_EXTENT;

	/*
	 * FIXME: pin buffers early may be inefficient. We can delay to
	 * prepare buffers until map_region() was done.
	 */
	buffer = blockget(mapping(inode), index++);
	if (!buffer)
		return -EIO;
	ret = bufvec_contig_add(bufvec, buffer);
	assert(ret);

	while (index < limit) {
		struct buffer_head *nextbuf = peekblk(buffer->map, index);
		if (nextbuf) {
			unsigned stop = !buffer_empty(nextbuf);
			if (stop) {
				blockput(nextbuf);
				break;
			}
		} else {
			nextbuf = blockget(buffer->map, index);
			if (!nextbuf)
				break;
		}
		ret = bufvec_contig_add(bufvec, nextbuf);
		assert(ret);

		index++;
	}

	return 0;
}

/* For read end I/O */
static void filemap_read_endio(struct buffer_head *buffer, int err)
{
	if (err) {
		/* FIXME: What to do? Hack: This re-link to state from bufvec */
		assert(0);
		__set_buffer_empty(buffer);
	} else {
		set_buffer_clean(buffer);
	}
	/* This drops refcount for bufvec of guess_readahead() */
	blockput(buffer);
}

/* For hole region */
static void filemap_hole_endio(struct buffer_head *buffer, int err)
{
	assert(err == 0);
	memset(bufdata(buffer), 0, bufsize(buffer));
	set_buffer_clean(buffer);
	/* This drops refcount for bufvec of guess_readahead() */
	blockput(buffer);
}

/* For readahead cleanup */
static void filemap_clean_endio(struct buffer_head *buffer, int err)
{
	assert(err == 0);
	__set_buffer_empty(buffer);
	/* This drops refcount for bufvec of guess_readahead() */
	blockput(buffer);
}

/* For write end I/O */
static void filemap_write_endio(struct buffer_head *buffer, int err)
{
	int forked = hlist_unhashed(&buffer->hashlink);

	if (err) {
		/* FIXME: What to do? Hack: This re-link to state from bufvec */
		assert(0);
		set_buffer_empty(buffer);
	} else
		set_buffer_clean(buffer);

	/* Is this forked buffer? */
	if (forked) {
		/* We have to unpin forked buffer to free. See blockdirty() */
		blockput(buffer);
	}
}

static int filemap_extent_io(enum map_mode mode, struct bufvec *bufvec)
{
	struct inode *inode = buffer_inode(bufvec_contig_buf(bufvec));
	block_t block, index = bufvec_contig_index(bufvec);
	int err, rw = (mode == MAP_READ) ? READ : WRITE;

	/* FIXME: now assuming buffer is only 1 for MAP_READ */
	assert(mode != MAP_READ || bufvec_contig_count(bufvec) == 1);
	err = filemap_bufvec_check(bufvec, mode);
	if (err)
		return err;

	struct bufvec *bufvec_io, bufvec_ahead;
	unsigned count;
	if (rw == READ) {
		/* In the case of read, use new bufvec for readahead */
		err = guess_readahead(&bufvec_ahead, inode, index);
		if (err)
			return err;
		bufvec_io = &bufvec_ahead;
	} else {
		bufvec_io = bufvec;
	}
	count = bufvec_contig_count(bufvec_io);

	struct seg map[10];

	int segs = map_region(inode, index, count, map, ARRAY_SIZE(map), mode);
	if (segs < 0)
		return segs;
	assert(segs);

	for (int i = 0; i < segs; i++) {
		block = map[i].block;
		count = map[i].count;

		trace("extent 0x%Lx/%x => %Lx", index, count, block);

		if (map[i].state != SEG_HOLE) {
			if (rw == READ)
				bufvec_io->end_io = filemap_read_endio;
			else
				bufvec_io->end_io = filemap_write_endio;

			err = blockio_vec(rw, bufvec_io, block, count);
			if (err)
				break;
		} else {
			assert(rw == READ);
			bufvec_io->end_io = filemap_hole_endio;
			bufvec_complete_without_io(bufvec_io, count);
		}

		index += count;
	}

	/*
	 * In the write case, bufvec owner is caller. And caller must
	 * be handle buffers was not mapped (and is not written out)
	 * this time.
	 */
	if (rw == READ) {
		/* Clean buffers was not mapped in this time */
		count = bufvec_contig_count(bufvec_io);
		if (count) {
			bufvec_io->end_io = filemap_clean_endio;
			bufvec_complete_without_io(bufvec_io, count);
		}
		bufvec_free(bufvec_io);
	}

	return err;
}

static int tuxio(struct file *file, void *data, unsigned len, int write)
{
	struct inode *inode = file->f_inode;
	struct sb *sb = tux_sb(inode->i_sb);
	loff_t pos = file->f_pos;
	int err = 0;

	trace("%s %u bytes at %Lu, isize = 0x%Lx",
	      write ? "write" : "read", len, (s64)pos, (s64)inode->i_size);

	if (write && pos + len > MAX_FILESIZE)
		return -EFBIG;
	if (!write && pos + len > inode->i_size) {
		if (pos >= inode->i_size)
			return 0;
		len = inode->i_size - pos;
	}

	if (write)
		inode->i_mtime = inode->i_ctime = gettime();

	unsigned bbits = sb->blockbits;
	unsigned bsize = sb->blocksize;
	unsigned bmask = sb->blockmask;

	loff_t tail = len;
	while (tail) {
		struct buffer_head *buffer, *clone;
		unsigned from = pos & bmask;
		unsigned some = from + tail > bsize ? bsize - from : tail;
		int full = write && some == bsize;

		if (full)
			buffer = blockget(mapping(inode), pos >> bbits);
		else
			buffer = blockread(mapping(inode), pos >> bbits);
		if (!buffer) {
			err = -EIO;
			break;
		}

		if (write) {
			clone = blockdirty(buffer, sb->delta);
			if (IS_ERR(clone)) {
				blockput(buffer);
				err = PTR_ERR(clone);
				break;
			}

			memcpy(bufdata(clone) + from, data, some);
			mark_buffer_dirty_non(clone);
		} else {
			clone = buffer;
			memcpy(data, bufdata(clone) + from, some);
		}

		trace_off("transfer %u bytes, block 0x%Lx, buffer %p",
			  some, bufindex(clone), buffer);

		blockput(clone);

		tail -= some;
		data += some;
		pos += some;
	}
	file->f_pos = pos;

	if (write) {
		if (inode->i_size < pos)
			inode->i_size = pos;
		mark_inode_dirty(inode);
	}

	return err ? err : len - tail;
}

int tuxread(struct file *file, void *data, unsigned len)
{
	return tuxio(file, data, len, 0);
}

int tuxwrite(struct file *file, const void *data, unsigned len)
{
	struct sb *sb = file->f_inode->i_sb;
	int ret;
	change_begin(sb);
	ret = tuxio(file, (void *)data, len, 1);
	change_end(sb);
	return ret;
}

void tuxseek(struct file *file, loff_t pos)
{
	warn("seek to 0x%Lx", (s64)pos);
	file->f_pos = pos;
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
	struct file file = { .f_inode = inode, };
	int ret;

	assert(inode->i_size == 0);
	ret = tuxio(&file, (void *)symname, len, 1);
	if (ret < 0)
		return ret;
	if (len != ret)
		return -EIO;
	return 0;
}

int page_readlink(struct inode *inode, void *buf, unsigned size)
{
	struct file file = { .f_inode = inode, };
	unsigned len = min_t(loff_t, inode->i_size, size);
	int ret;

	ret = tuxread(&file, buf, len);
	if (ret < 0)
		return ret;
	if (ret != len)
		return -EIO;
	return 0;
}
