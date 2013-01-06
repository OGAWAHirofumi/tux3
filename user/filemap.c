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

/*
 * Extrapolate from single buffer blockread to opportunistic extent IO
 *
 * Essentially readahead:
 *  - stop at first present buffer
 *  - stop at end of file
 *
 * Stop when extent is "big enough", whatever that means.
 */
static unsigned guess_readahead(struct buffer_head *buffer)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = inode->i_sb;
	block_t limit = (inode->i_size + sb->blockmask) >> sb->blockbits;
	block_t index = bufindex(buffer);
	unsigned count = 1;

	while (count < MAX_EXTENT) {
		block_t next = index + count;

		if (next >= limit)
			break;

		struct buffer_head *nextbuf = peekblk(buffer->map, next);
		if (nextbuf) {
			unsigned stop = !buffer_empty(nextbuf);
			blockput(nextbuf);
			if (stop)
				break;
		}
		count++;
	}

	return count;
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

static int filemap_extent_io(struct buffer_head *buffer, enum map_mode mode)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);

	trace("%s inode 0x%Lx block 0x%Lx",
	      (mode == MAP_READ) ? "read" :
			(mode == MAP_WRITE) ? "write" : "redirect",
	      tux_inode(inode)->inum, bufindex(buffer));

	if (bufindex(buffer) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;

	if (mode != MAP_READ && buffer_empty(buffer))
		warn("egad, writing an invalid buffer");
	if (mode == MAP_READ && buffer_dirty(buffer))
		warn("egad, reading a dirty buffer");

	block_t index = bufindex(buffer);
	unsigned count = 1;
	if (mode == MAP_READ)
		count = guess_readahead(buffer);

	trace("---- extent 0x%Lx/%x ----\n", index, count);

	struct seg map[10];

	int segs = map_region(inode, index, count, map, ARRAY_SIZE(map), mode);
	if (segs < 0)
		return segs;

	if (!segs) {
		if (mode == MAP_READ) {
			trace("unmapped block %Lx", bufindex(buffer));
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_clean(buffer);
			return 0;
		}
		return -EIO;
	}

	int err = 0, rw = (mode == MAP_READ) ? READ : WRITE;
	for (int i = 0; !err && i < segs; i++) {
		int hole = map[i].state == SEG_HOLE;

		trace("extent 0x%Lx/%x => %Lx",
		      index, map[i].count, map[i].block);

		for (int j = 0; !err && j < map[i].count; j++) {
			block_t block = map[i].block + j;

			if (rw == READ) {
				buffer = blockget(mapping(inode), index + j);
				if (!buffer) {
					err = -ENOMEM;
					break;
				}
			}

			trace("block 0x%Lx => %Lx", bufindex(buffer), block);
			if (hole) {
				assert(rw == READ);
				memset(bufdata(buffer), 0, sb->blocksize);
			} else
				err = blockio(rw, buffer, block);

			/* FIXME: leave empty if error ??? */
			clean_buffer(buffer);
			if (rw == READ)
				blockput(buffer);
		}
		index += map[i].count;
	}
	return err;
}

int filemap_overwrite_io(struct buffer_head *buffer, int write)
{
	enum map_mode mode = write ? MAP_WRITE : MAP_READ;
	return filemap_extent_io(buffer, mode);
}

int filemap_redirect_io(struct buffer_head *buffer, int write)
{
	enum map_mode mode = write ? MAP_REDIRECT : MAP_READ;
	return filemap_extent_io(buffer, mode);
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
