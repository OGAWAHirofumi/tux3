#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

#include "kernel/filemap.c"

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
#ifndef ATOMIC
	return buffer;
#endif
	assert(buffer->state < BUFFER_STATES);

	trace("---- before: fork buffer %p ----", buffer);
	if (buffer_dirty(buffer)) {
		if (buffer_can_modify(buffer, newdelta))
			return buffer;

		/* Buffer can't modify already, we have to fork buffer */
		trace("---- fork buffer %p ----", buffer);
		struct buffer_head *clone = new_buffer(buffer->map);
		if (IS_ERR(clone))
			return clone;
		/* Create the cloned buffer */
		memcpy(bufdata(clone), bufdata(buffer), bufsize(buffer));
		clone->index = buffer->index;
		/* Replace the buffer by cloned buffer. */
		remove_buffer_hash(buffer);
		insert_buffer_hash(clone);

		/*
		 * The refcount of buffer is used for backend. So, the
		 * backend has to free this buffer (blockput(buffer))
		 */
		buffer = clone;
	}

	set_buffer_dirty_when(buffer, newdelta);
	__mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);

	return buffer;
}

static int filemap_bufvec_check(struct bufvec *bufvec, enum map_mode mode)
{
	trace("%s inode 0x%Lx block 0x%Lx",
	      (mode == MAP_READ) ? "read" :
			(mode == MAP_WRITE) ? "write" : "redirect",
	      buffer_inode(bufvec->bufv[bufvec->pos])->inum,
	      bufvec_first_index(bufvec));

	if (bufvec_last_index(bufvec) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;

	for (unsigned i = 0; i < bufvec_inuse(bufvec); i++) {
		struct buffer_head *buffer = bufvec_bufv(bufvec)[i];

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
static struct bufvec *guess_readahead(struct inode *inode, block_t index)
{
	struct sb *sb = inode->i_sb;
	block_t limit = (inode->i_size + sb->blockmask) >> sb->blockbits;
	struct bufvec *bufvec;
	struct buffer_head *buffer;
	int ret;

	/* FIXME: MAX_EXTENT is not true for dleaf2 */
	bufvec = bufvec_alloc(MAX_EXTENT);
	if (!bufvec)
		return NULL;

	/*
	 * FIXME: pin buffers early may be inefficient. We can delay to
	 * prepare buffers until map_region() was done.
	 */
	buffer = blockget(mapping(inode), index++);
	if (!buffer)
		return NULL;
	ret = bufvec_add(bufvec, buffer);
	assert(ret);

	while (bufvec_space(bufvec)) {
		if (index >= limit)
			break;

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
		ret = bufvec_add(bufvec, nextbuf);
		assert(ret);

		index++;
	}

	return bufvec;
}

static void clean_buffer(struct buffer_head *buffer)
{
	/* Is this forked buffer? */
	if (hlist_unhashed(&buffer->hashlink)) {
		/* We have to unpin forked buffer to free. See blockdirty() */
		set_buffer_clean(buffer);
		blockput(buffer);
	} else
		set_buffer_clean(buffer);
}

static int filemap_extent_io(struct bufvec *bufvec, enum map_mode mode)
{
	struct inode *inode = buffer_inode(bufvec_first_buf(bufvec));
	struct sb *sb = tux_sb(inode->i_sb);
	block_t block, index = bufvec_first_index(bufvec);
	int err, rw = (mode == MAP_READ) ? READ : WRITE;

	/* FIXME: now assuming buffer is only 1 for MAP_READ */
	assert(mode != MAP_READ || bufvec_inuse(bufvec) == 1);
	err = filemap_bufvec_check(bufvec, mode);
	if (err)
		return err;

	struct bufvec *bufvec_io;
	unsigned count;
	if (rw == READ) {
		/* In the case of read, use new bufvec for readahead */
		bufvec_io = guess_readahead(inode, index);
		if (!bufvec_io)
			return -ENOMEM;
	} else {
		bufvec_io = bufvec;
	}
	count = bufvec_inuse(bufvec_io);

	struct seg map[10];

	int segs = map_region(inode, index, count, map, ARRAY_SIZE(map), mode);
	if (segs < 0)
		return segs;
	if (!segs) {
		if (rw == WRITE)
			return -EIO;

		trace("unmapped block %Lx", index);
		/* There was no extent, handle as hole */
		segs = 1;
		map[0].block = 0;
		map[0].count = bufvec_inuse(bufvec);
		map[0].state = SEG_HOLE;
	}

	for (int i = 0; i < segs; i++) {
		block = map[i].block;
		count = map[i].count;

		assert(rw == READ || map[i].state != SEG_HOLE);
		trace("extent 0x%Lx/%x => %Lx", index, count, block);

		if (map[i].state != SEG_HOLE) {
			err = blockio_vec(rw, bufvec_io, count, block);
			if (err)
				break;
		}

		for (unsigned j = 0; j < count; j++) {
			struct buffer_head *buffer = bufvec_bufv(bufvec_io)[j];

			if (map[i].state == SEG_HOLE)
				memset(bufdata(buffer), 0, sb->blocksize);

			/* FIXME: leave empty if error ??? */
			if (rw == READ) {
				set_buffer_clean(buffer);
				blockput(buffer);
			} else
				clean_buffer(buffer);
		}

		bufvec_io_done(bufvec_io, count);
		index += count;
	}

	/*
	 * In the write case, bufvec owner is caller. And caller must
	 * be handle buffers was not mapped (and is not written out)
	 * this time.
	 */
	if (rw == READ) {
		/* Clean buffers was not mapped in this time */
		for (unsigned i = 0; i < bufvec_inuse(bufvec_io); i++)
			blockput(bufvec_bufv(bufvec_io)[i]);
		bufvec_free(bufvec_io);
	}

	return err;
}

int filemap_overwrite_io(struct bufvec *bufvec, int rw)
{
	enum map_mode mode = (rw == READ) ? MAP_READ : MAP_WRITE;
	return filemap_extent_io(bufvec, mode);
}

int filemap_redirect_io(struct bufvec *bufvec, int rw)
{
	enum map_mode mode = (rw == READ) ? MAP_READ : MAP_REDIRECT;
	return filemap_extent_io(bufvec, mode);
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
