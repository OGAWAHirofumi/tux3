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
	unsigned oldstate = buffer->state;
	assert(oldstate < BUFFER_STATES);
	newdelta &= BUFFER_DIRTY_STATES - 1;
	trace_on("---- before: fork buffer %p ----", buffer);
	if (oldstate >= BUFFER_DIRTY) {
		if (oldstate - BUFFER_DIRTY == newdelta)
			return buffer;
		trace_on("---- fork buffer %p ----", buffer);
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
	set_buffer_state_list(buffer, BUFFER_DIRTY + newdelta, &buffer->map->dirty);
	__mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);

	return buffer;
}

/*
 * Extrapolate from single buffer flush or blockread to opportunistic exent IO
 *
 * For write, try to include adjoining buffers above and below:
 *  - stop at first uncached or clean buffer in either direction
 *
 * For read (essentially readahead):
 *  - stop at first present buffer
 *  - stop at end of file
 *
 * For both, stop when extent is "big enough", whatever that means.
 */
static void guess_region(struct buffer_head *buffer, block_t *start, unsigned *count, int write)
{
	struct inode *inode = buffer_inode(buffer);
	block_t ends[2] = { bufindex(buffer), bufindex(buffer) };
	for (int up = !write; up < 2; up++) {
		while (ends[1] - ends[0] + 1 < MAX_EXTENT) {
			block_t next = ends[up] + (up ? 1 : -1);
			struct buffer_head *nextbuf = peekblk(buffer->map, next);
			if (!nextbuf) {
				if (write)
					break;
				if (next > inode->i_size >> tux_sb(inode->i_sb)->blockbits)
					break;
			} else {
				unsigned stop = write ? !buffer_dirty(nextbuf) : !buffer_empty(nextbuf);
				blockput(nextbuf);
				if (stop)
					break;
			}
			ends[up] = next; /* what happens to the beer you send */
		}
	}
	*start = ends[0];
	*count = ends[1] + 1 - ends[0];
}

int filemap_extent_io(struct buffer_head *buffer, int write)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);
	trace("%s inode 0x%Lx block 0x%Lx", write ? "write" : "read", (L)tux_inode(inode)->inum, (L)bufindex(buffer));
	if (bufindex(buffer) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	struct dev *dev = sb->dev;
	assert(dev->bits >= 8 && dev->fd);
	if (write && buffer_empty(buffer))
		warn("egad, writing an invalid buffer");
	if (!write && buffer_dirty(buffer))
		warn("egad, reading a dirty buffer");

	block_t start;
	unsigned count;
	guess_region(buffer, &start, &count, write);
	printf("---- extent 0x%Lx/%x ----\n", (L)start, count);

	struct seg map[10];

	int segs = map_region(inode, start, count, map, ARRAY_SIZE(map), write);
	if (segs < 0)
		return segs;

	if (!segs) {
		if (!write) {
			trace("unmapped block %Lx", (L)bufindex(buffer));
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_clean(buffer);
			return 0;
		}
		return -EIO;
	}

	int err = 0;
	for (int i = 0, index = start; !err && i < segs; i++) {
		int hole = map[i].state == SEG_HOLE;
		trace_on("extent 0x%Lx/%x => %Lx", (L)index, map[i].count, (L)map[i].block);
		for (int j = 0; !err && j < map[i].count; j++) {
			block_t block = map[i].block + j;
			buffer = blockget(mapping(inode), index + j);
			trace_on("block 0x%Lx => %Lx", (L)bufindex(buffer), (L)block);
			if (write) {
				err = blockio(WRITE, buffer, block);
			} else {
				if (hole)
					memset(bufdata(buffer), 0, sb->blocksize);
				else
					err = blockio(READ, buffer, block);
			}
			blockput(set_buffer_clean(buffer)); // leave empty if error ???
		}
		index += map[i].count;
	}
	return err;
}

/*
 * FIXME: temporary hack.  The bitmap pages has possibility to
 * blockfork. It means we can't get the page buffer with blockget(),
 * because it gets cloned buffer for frontend. But, in here, we are
 * interest older buffer to write out. So, for now, this is grabbing
 * old buffer while blockfork.
 *
 * This is why we can't use filemap_extent_io() simply.
 */
int write_bitmap(struct buffer_head *buffer)
{
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
	struct seg seg;
	int err = map_region(buffer->map->inode, buffer->index, 1, &seg, 1, 2);
	if (err < 0)
		return err;
	assert(err == 1);
	assert(buffer->state - BUFFER_DIRTY == ((sb->rollup - 1) & (BUFFER_DIRTY_STATES - 1)));
	trace("write bitmap %Lx", (L)buffer->index);
	err = blockio(WRITE, buffer, seg.block);
	if (!err)
		clean_buffer(buffer);
	return 0;
}
