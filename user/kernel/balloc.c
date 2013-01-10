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

	printf("%Ld bitmap blocks:\n", blocks);
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
				printf("[%Lx] ", block);
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
						printf("-%Lx ", found - 1);
					else if (begin == found - 1)
						printf("%Lx ", begin);
					else
						printf("%Lx-%Lx ", begin, found - 1);
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
			printf("%Lx-", begin);
		if (any)
			printf("\n");
	}
	printf("(%Ld active)\n", active);
	return -1;
}
#endif

/* userland only */
block_t balloc_from_range(struct sb *sb, block_t start, block_t count,
			  unsigned blocks)
{
	struct inode *inode = sb->bitmap;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	block_t limit = start + count;
	block_t mapblocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3;

	trace("balloc find %i blocks, range [%Lx, %Lx]", blocks, start, count);
	assert(blocks > 0);
	assert(tux3_under_backend(sb));

	for (block_t mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		struct buffer_head *buffer, *clone;

		buffer = blockread(mapping(inode), mapblock);
		if (!buffer) {
			warn("block read failed");
			// !!! error return sucks here
			return -EIO;
		}

		unsigned bytes = sb->blocksize - offset, run = 0;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = bufdata(buffer) + offset, *top = p + bytes, c;
		for (; p < top; p++, startbit = 0) {
			if ((c = *p) == 0xff) {
				run = 0;
				continue;
			}
			for (int i = startbit, mask = 1 << startbit; i < 8; i++, mask <<= 1) {
				if ((c & mask)) {
					run = 0;
					continue;
				}
				if (++run < blocks)
					continue;
				assert(run == blocks);
				block_t found = i + (((void *)p - bufdata(buffer)) << 3) + (mapblock << mapshift);
				if (found >= limit) {
					assert(mapblock == mapblocks - 1);
					goto final_partial_byte;
				}
				found -= run - 1;

				/*
				 * The bitmap is modified only by backend.
				 * blockdirty() should never return -EAGAIN.
				 */
				clone = blockdirty(buffer, sb->rollup);
				if (IS_ERR(clone)) {
					assert(PTR_ERR(clone) != -EAGAIN);
					blockput(buffer);
					/* FIXME: error handling */
					return -EIO;
				}
				set_bits(bufdata(clone), found & mapmask, run);
				mark_buffer_dirty_non(clone);
				blockput(clone);
				sb->nextalloc = found + run;
				sb->freeblocks -= run;
				//set_sb_dirty(sb);

				trace("balloc extent [block %Lx, count %x]",
				      found, blocks);

				return found;
			}
		}
final_partial_byte:
		blockput(buffer);
		tail -= bytes;
		offset = 0;
	}

	return -ENOSPC;
}

int balloc(struct sb *sb, unsigned blocks, block_t *block)
{
	block_t ret, goal = sb->nextalloc, total = sb->volblocks;

	ret = balloc_from_range(sb, goal, total - goal, blocks);
	if (goal && ret == -ENOSPC)
		ret = balloc_from_range(sb, 0, goal, blocks);

	if (ret < 0) {
		if (ret == -ENOSPC) {
			/* FIXME: This is for debugging. Remove this */
			warn("couldn't balloc: blocks %u", blocks);
		}
		return ret;
	}

	/* Set allocated block */
	*block = ret;

	return 0;
}

int bfree(struct sb *sb, block_t start, unsigned blocks)
{
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	block_t mapblock = start >> mapshift;
	unsigned mapoffset = start & mapmask;
	struct buffer_head *buffer, *clone;

	assert(blocks > 0);
	assert(tux3_under_backend(sb));

	buffer = blockread(mapping(sb->bitmap), mapblock);
	if (!buffer) {
		warn("couldn't read bitmap buffer: extent 0x%Lx\n", start);
		goto error;
	}

	if (!all_set(bufdata(buffer), mapoffset, blocks))
		goto double_free;

	/*
	 * The bitmap is modified only by backend.
	 * blockdirty() should never return -EAGAIN.
	 */
	clone = blockdirty(buffer, sb->rollup);
	if (IS_ERR(clone)) {
		assert(PTR_ERR(clone) != -EAGAIN);
		blockput(buffer);
		/* FIXME: error handling */
		return PTR_ERR(clone);
	}
	clear_bits(bufdata(clone), mapoffset, blocks);
	mark_buffer_dirty_non(clone);
	blockput(clone);

	sb->freeblocks += blocks;
	//set_sb_dirty(sb);

	trace("bfree extent [block %Lx, count %x], ", start, blocks);

	return 0;

double_free:
	error("double free: start 0x%Lx, blocks %x", start, blocks);
	blockput(buffer);
error:
	return -EIO; // error???
}

int replay_update_bitmap(struct replay *rp, block_t start, unsigned count,
			 int set)
{
	struct sb *sb = rp->sb;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	block_t mapblock = start >> mapshift;
	unsigned mapoffset = start & mapmask;
	struct buffer_head *buffer, *clone;

	buffer = blockread(mapping(sb->bitmap), mapblock);
	if (!buffer)
		return -ENOMEM;

	if (!(set ? all_clear : all_set)(bufdata(buffer), mapoffset, count)) {
		blockput(buffer);

		error("%s: start 0x%Lx, count %x",
		      set ? "already allocated" : "double free",
		      start, count);
		return -EINVAL;
	}

	/*
	 * The bitmap is modified only by backend.
	 * blockdirty() should never return -EAGAIN.
	 */
	clone = blockdirty(buffer, sb->rollup);
	if (IS_ERR(clone)) {
		assert(PTR_ERR(clone) != -EAGAIN);
		blockput(buffer);
		/* FIXME: error handling */
		return PTR_ERR(clone);
	}
	(set ? set_bits : clear_bits)(bufdata(clone), mapoffset, count);
	mark_buffer_dirty_non(clone);
	blockput(clone);

	if (set)
		sb->freeblocks -= count;
	else
		sb->freeblocks += count;

	return 0;
}
