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

/* For lockdep: random value bigger than max of inode_i_mutex_lock_class */
#define I_MUTEX_BITMAP	7

#ifndef __KERNEL__
block_t count_range(struct inode *inode, block_t start, block_t count)
{
	assert(!(start & 7));
	unsigned char ones[256];
	for (int i = 0; i < sizeof(ones); i++)
		ones[i] = bytebits(i);

	struct sb *sb = tux_sb(inode->i_sb);
	block_t limit = start + count;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	block_t tail = (count + 7) >> 3, total = 0;

	for (unsigned block = start >> mapshift; block < blocks; block++) {
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
	block_t limit = start + count;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift, active = 0;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3, begin = -1;

	printf("%i bitmap blocks:\n", blocks);
	for (unsigned block = start >> mapshift; block < blocks; block++) {
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
				printf("[%x] ", block);
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
	printf("(%i active)\n", active);
	return -1;
}
#endif

/* userland only */
block_t balloc_from_range(struct sb *sb, block_t start, unsigned count, unsigned blocks)
{
	struct inode *inode = sb->bitmap;
	trace_off("balloc %i blocks from [%Lx/%x]", blocks, start, count);
	assert(blocks > 0);
	block_t limit = start + count;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned mapblocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3;

	for (unsigned mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		trace_off("search mapblock %x/%x", mapblock, mapblocks);
		struct buffer_head *buffer = blockread(mapping(inode), mapblock);
		if (!buffer) {
			warn("block read failed"); // !!! error return sucks here
			return -1;
		}
		mutex_lock_nested(&sb->bitmap->i_mutex, I_MUTEX_BITMAP);
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
				buffer = blockdirty(buffer, sb->rollup);
				// FIXME: error check of buffer
				set_bits(bufdata(buffer), found & mapmask, run);
				mark_buffer_dirty_non(buffer);
				blockput(buffer);
				sb->nextalloc = found + run;
				sb->freeblocks -= run;
				//set_sb_dirty(sb);
				mutex_unlock(&sb->bitmap->i_mutex);
				trace("balloc extent -> [%Lx/%x]", found, blocks);
				return found;
			}
		}
final_partial_byte:
		mutex_unlock(&sb->bitmap->i_mutex);
		blockput(buffer);
		tail -= bytes;
		offset = 0;
	}
	return -1;
}

int balloc(struct sb *sb, unsigned blocks, block_t *block)
{
	assert(blocks > 0);
	trace_off("balloc %x blocks at goal %Lx", blocks, sb->nextalloc);
	block_t goal = sb->nextalloc, total = sb->volblocks;

	if ((*block = balloc_from_range(sb, goal, total - goal, blocks)) >= 0)
		goto found;
	if ((*block = balloc_from_range(sb, 0, goal, blocks)) >= 0)
		goto found;
	return -ENOSPC;
found:
	return 0;
}

int bfree(struct sb *sb, block_t start, unsigned blocks)
{
	assert(blocks > 0);
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned mapblock = start >> mapshift;
	struct buffer_head *buffer;

	buffer = blockread(mapping(sb->bitmap), mapblock);
	if (!buffer) {
		warn("couldn't read bitmap buffer: extent 0x%Lx\n", start);
		goto error;
	}

	mutex_lock_nested(&sb->bitmap->i_mutex, I_MUTEX_BITMAP);
	if (!all_set(bufdata(buffer), start &= mapmask, blocks))
		goto double_free;
	trace("bfree extent <- [%Lx/%x], ", start, blocks);
	buffer = blockdirty(buffer, sb->rollup);
	// FIXME: error check of buffer
	clear_bits(bufdata(buffer), start, blocks);
	mark_buffer_dirty_non(buffer);
	blockput(buffer);
	sb->freeblocks += blocks;
	//set_sb_dirty(sb);
	mutex_unlock(&sb->bitmap->i_mutex);

	return 0;

double_free:
	error("double free: start 0x%Lx, blocks %x", start, blocks);
	mutex_unlock(&sb->bitmap->i_mutex);
	blockput(buffer);
error:
	return -EIO; // error???
}

int replay_update_bitmap(struct replay *rp, block_t start, unsigned count,
			 int set)
{
	struct sb *sb = rp->sb;
	unsigned shift = sb->blockbits + 3, mask = (1 << shift) - 1;
	struct buffer_head *buffer = blockread(mapping(sb->bitmap), start >> shift);

	if (!buffer)
		return -ENOMEM;

	if (!(set ? all_clear : all_set)(bufdata(buffer), start & mask, count)) {
		blockput(buffer);

		error("%s: start 0x%Lx, count %x",
		      set ? "already allocated" : "double free",
		      start, count);
		return -EINVAL;
	}

	buffer = blockdirty(buffer, sb->rollup);
	(set ? set_bits : clear_bits)(bufdata(buffer), start & mask, count);
	mark_buffer_dirty_non(buffer);
	blockput(buffer);

	if (set)
		sb->freeblocks -= count;
	else
		sb->freeblocks += count;

	return 0;
}
