/*
 * Block allocation
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 2
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

/*
 * Group counts
 */

static int countmap_load(struct sb *sb, block_t group)
{
	block_t block = group >> (sb->blockbits - 1);
	struct countmap_pin *pin = &sb->countmap_pin;

	if (!pin->buffer || bufindex(pin->buffer) != block) {
		if (pin->buffer)
			blockput(pin->buffer);
		pin->buffer = blockread(mapping(sb->countmap), block);
		if (!pin->buffer) {
			tux3_err(sb, "block read failed");
			return -EIO;
		}
	}
	return 0;
}

static int countmap_add(struct sb *sb, block_t group, int count)
{
	unsigned offset = group & (sb->blockmask >> 1);
	struct buffer_head *clone;
	__be16 *p;
	int err;

	err = countmap_load(sb, group);
	if (err)
		return err;
	trace("add %d to group %Lu", count, group);
	/*
	 * The countmap is modified only by backend.  blockdirty()
	 * should never return -EAGAIN.
	 */
	clone = blockdirty(sb->countmap_pin.buffer, sb->unify);
	if (IS_ERR(clone)) {
		err = PTR_ERR(clone);
		assert(err != -EAGAIN);
		return err;
	}
	sb->countmap_pin.buffer = clone;

	p = bufdata(sb->countmap_pin.buffer);
	be16_add_cpu(p + offset, count);

	return 0;
}

void countmap_put(struct countmap_pin *pin)
{
	if (pin->buffer) {
		blockput(pin->buffer);
		pin->buffer = NULL;
	}
}

/*
 * Bitmap
 */

#ifndef __KERNEL__
block_t count_range(struct inode *inode, block_t start, block_t count)
{
	unsigned char ones[256];

	assert(!(start & 7));

	for (int i = 0; i < sizeof(ones); i++)
		ones[i] = bytebits(i);

	struct sb *sb = tux_sb(inode->i_sb);
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	block_t limit = start + count;
	block_t blocks = (limit + mapmask) >> mapshift;
	block_t tail = (count + 7) >> 3, total = 0;
	unsigned offset = (start & mapmask) >> 3;

	for (block_t block = start >> mapshift; block < blocks; block++) {
		//trace("count block %x/%x", block, blocks);
		struct buffer_head *buffer = blockread(mapping(inode), block);
		if (!buffer)
			return -1;
		unsigned bytes = sb->blocksize - offset;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = bufdata(buffer) + offset, *top = p + bytes;
		while (p < top)
			total += ones[*p++];
		blockput(buffer);
		tail -= bytes;
		offset = 0;
	}
	return total;
}

block_t bitmap_dump(struct inode *inode, block_t start, block_t count)
{
	struct sb *sb = tux_sb(inode->i_sb);
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	block_t limit = start + count;
	block_t blocks = (limit + mapmask) >> mapshift, active = 0;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3, begin = -1;

	__tux3_dbg("%Ld bitmap blocks:\n", blocks);
	for (block_t block = start >> mapshift; block < blocks; block++) {
		int ended = 0, any = 0;
		struct buffer_head *buffer = blockread(mapping(inode), block);
		if (!buffer)
			return -1;
		unsigned bytes = sb->blocksize - offset;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = bufdata(buffer) + offset, *top = p + bytes;
		for (; p < top; p++, startbit = 0) {
			unsigned c = *p;
			if (!any && c)
				__tux3_dbg("[%Lx] ", block);
			any |= c;
			if ((!c && begin < 0) || (c == 0xff && begin >= 0))
				continue;
			for (int i = startbit, mask = 1 << startbit; i < 8; i++, mask <<= 1) {
				if (!(c & mask) == (begin < 0))
					continue;
				block_t found = i + (((void *)p - bufdata(buffer)) << 3) + (block << mapshift);
				if (begin < 0)
					begin = found;
				else {
					if ((begin >> mapshift) != block)
						__tux3_dbg("-%Lx ", found - 1);
					else if (begin == found - 1)
						__tux3_dbg("%Lx ", begin);
					else
						__tux3_dbg("%Lx-%Lx ", begin, found - 1);
					begin = -1;
					ended++;
				}
			}
		}
		active += !!any;
		blockput(buffer);
		tail -= bytes;
		offset = 0;
		if (begin >= 0)
			__tux3_dbg("%Lx-", begin);
		if (any)
			__tux3_dbg("\n");
	}
	__tux3_dbg("(%Ld active)\n", active);
	return -1;
}
#endif

/*
 * Modify bits on one block, then adjust ->freeblocks.
 */
static int bitmap_modify_bits(struct sb *sb, struct buffer_head *buffer,
			      unsigned offset, unsigned blocks, int set)
{
	struct buffer_head *clone;
	void (*modify)(u8 *, unsigned, unsigned) = set ? set_bits : clear_bits;

	assert(blocks > 0);
	assert(offset + blocks <= sb->blocksize << 3);

	/*
	 * The bitmap is modified only by backend.
	 * blockdirty() should never return -EAGAIN.
	 */
	clone = blockdirty(buffer, sb->unify);
	if (IS_ERR(clone)) {
		int err = PTR_ERR(clone);
		assert(err != -EAGAIN);
		return err;
	}

	modify(bufdata(clone), offset, blocks);

	mark_buffer_dirty_non(clone);
	blockput(clone);

	if (set)
		sb->freeblocks -= blocks;
	else
		sb->freeblocks += blocks;

	return 0;
}

/*
 * If bits on multiple blocks is excepted state, modify bits.
 *
 * FIXME: If error happened on middle of blocks, modified bits and
 * ->freeblocks are not restored to original. What to do?
 */
static int __bitmap_modify(struct sb *sb, block_t start, unsigned blocks,
			   int set, int (*test)(u8 *, unsigned, unsigned))
{
	struct inode *bitmap = sb->bitmap;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapsize = 1 << mapshift;
	unsigned mapmask = mapsize - 1;
	unsigned mapoffset = start & mapmask;
	block_t mapblock, mapblocks = (start + blocks + mapmask) >> mapshift;

	assert(blocks > 0);
	assert(start + blocks <= sb->volblocks);

	for (mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		struct buffer_head *buffer;
		unsigned len;
		int err;

		buffer = blockread(mapping(bitmap), mapblock);
		if (!buffer) {
			tux3_err(sb, "block read failed");
			// !!! error return sucks here
			return -EIO;
		}

		len = min(mapsize - mapoffset, blocks);
		if (test && !test(bufdata(buffer), mapoffset, len)) {
			blockput(buffer);

			tux3_fs_error(sb, "%s: start 0x%Lx, count %x",
				      set ? "already allocated" : "double free",
				      start, blocks);

			return -EIO;	/* FIXME: error code? */
		}

		err = bitmap_modify_bits(sb, buffer, mapoffset, len, set);
		if (err) {
			blockput(buffer);
			/* FIXME: error handling */
			return err;
		}

		mapoffset = 0;
		blocks -= len;
	}

	return countmap_add(sb, start >> sb->groupbits, set ? blocks : -blocks);
}

static int bitmap_modify(struct sb *sb, block_t start, unsigned blocks, int set)
{
	return __bitmap_modify(sb, start, blocks, set, NULL);
}

static int bitmap_test_and_modify(struct sb *sb, block_t start, unsigned blocks,
				  int set)
{
	int (*test)(u8 *, unsigned, unsigned) = set ? all_clear : all_set;
	return __bitmap_modify(sb, start, blocks, set, test);
}

static inline int mergable(struct block_segment *seg, block_t block)
{
	return seg->block + seg->count == block;
}

/*
 * Find blocks available in the specified range.
 *
 * NOTE: Caller must check "*block" to know how many blocks were
 * found. This returns 0 even if no blocks found.
 *
 * return value:
 * < 0 - error
 *   0 - succeed to check
 */
int balloc_find_range(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	block_t start, block_t range, unsigned *blocks)
{
	struct inode *bitmap = sb->bitmap;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapsize = 1 << mapshift;
	unsigned mapmask = mapsize - 1;
	struct buffer_head *buffer;

	trace("find %u blocks in [%Lu+%Lu], segs = %d",
	      *blocks, start, range, *segs);

	assert(*blocks > 0);
	assert(start < sb->volblocks);
	assert(start + range <= sb->volblocks);
	assert(*segs < maxsegs);
	assert(tux3_under_backend(sb));

	/* Search across blocks */
	while (range > 0) {
		block_t mapblock = start >> mapshift;
		block_t mapbase = mapblock << mapshift;
		unsigned offset = start & mapmask;
		unsigned maplimit = min_t(block_t, mapsize, offset + range);
		unsigned chunk = maplimit - offset;
		char *data;

		buffer = blockread(mapping(bitmap), mapblock);
		if (!buffer) {
			tux3_err(sb, "block read failed");
			return -EIO;
			/* FIXME: error handling */
		}
		data = bufdata(buffer);
		/* Search within block */
		do {
			block_t end = (block_t)offset + *blocks;
			unsigned limit, next;

			limit = min_t(block_t, end, maplimit);
			next = find_next_bit_le(data, limit, offset);

			if (next != offset) {
				unsigned count = next - offset;
				block_t found = mapbase + offset;

				if (*segs && mergable(&seg[*segs - 1], found)) {
					trace("append seg [%Lu+%u]", found, count);
					seg[*segs - 1].count += count;
				} else {
					trace("balloc seg [%Lu+%u]", found, count);
					seg[(*segs)++] = (struct block_segment){
						.block = found,
						.count = count,
					};
				}
				*blocks -= count;

				if (!*blocks || *segs == maxsegs) {
					blockput(buffer);
					return 0;
				}
			}

			offset = find_next_zero_bit_le(data, maplimit, next + 1);
			/* Remove after tested on arm. (next + 1 can
			 * be greater than maplimit) */
			assert(offset <= maplimit);
		} while (offset != maplimit);

		assert(start + chunk == mapbase + maplimit);
		start += chunk;
		range -= chunk;
		blockput(buffer);
	}

	return 0;
}

/*
 * Allocate block segments from entire volume.  Wrap to bottom of
 * volume if needed.
 *
 * return value:
 * < 0 - error
 *   0 - succeed to allocate blocks, at least >= 1
 */
int balloc_find(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	unsigned *blocks)
{
	block_t goal = sb->nextblock, volsize = sb->volblocks;
	int err, newsegs = 0;

	err = balloc_find_range(sb, seg, maxsegs, &newsegs, goal,
				volsize - goal, blocks);
	trace("=> try0: segs = %d, blocks = %u", newsegs, *blocks);
	if (err)
		return err;

	if (*blocks && newsegs < maxsegs) {
		err = balloc_find_range(sb, seg, maxsegs, &newsegs, 0, goal,
					blocks);
		trace("=> try1: segs = %d, blocks = %u", newsegs, *blocks);
		if (err < 0)
			return err;
	}

	if (!newsegs) {
		/* FIXME: This is for debugging. Remove this */
		tux3_warn(sb, "couldn't balloc: blocks %u, freeblocks %Lu",
			  *blocks, sb->freeblocks);
		return -ENOSPC;
	}

	*segs = newsegs;

	return 0;
}

int balloc_use(struct sb *sb, struct block_segment *seg, int segs)
{
	block_t goal;
	int i;

	assert(segs > 0);

	for (i = 0; i < segs; i++) {
		/* FIXME: error handling */
		int err = bitmap_modify(sb, seg[i].block, seg[i].count, 1);
		if (err)
			return err;
	}

	goal = seg[segs - 1].block + seg[segs - 1].count;
	sb->nextblock = goal == sb->volblocks ? 0 : goal;

	return 0;
}

int balloc_segs(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	unsigned *blocks)
{
	int err = balloc_find(sb, seg, maxsegs, segs, blocks);
	if (!err)
		err = balloc_use(sb, seg, *segs);
	return err;
}

block_t balloc_one(struct sb *sb)
{
	struct block_segment seg;
	unsigned blocks = 1;
	int err, segs;

	err = balloc_segs(sb, &seg, 1, &segs, &blocks);
	if (err)
		return err;
	assert(segs == 1 && blocks == 0 && seg.count == 1);
	return seg.block;
}

int bfree(struct sb *sb, block_t start, unsigned blocks)
{
	assert(tux3_under_backend(sb));
	trace("bfree extent [%Lu+%u], ", start, blocks);
	return bitmap_test_and_modify(sb, start, blocks, 0);
}

int bfree_segs(struct sb *sb, struct block_segment *seg, int segs)
{
	int i;
	for (i = 0; i < segs; i++) {
		/* FIXME: error handling */
		int err = bfree(sb, seg[i].block, seg[i].count);
		if (err)
			return err;
	}
	return 0;
}

int replay_update_bitmap(struct replay *rp, block_t start, unsigned blocks,
			 int set)
{
	return bitmap_test_and_modify(rp->sb, start, blocks, set);
}
