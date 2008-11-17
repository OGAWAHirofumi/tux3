/*
 * Block allocation
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
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

#ifndef trace
#define trace trace_off
#endif

void set_bits(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;
	if (loff == roff) {
		bitmap[loff] |= lmask & rmask;
		return;
	}
	bitmap[loff] |= lmask;
	memset(bitmap + loff + 1, -1, roff - loff - 1);
	if (rmask)
		bitmap[roff] |= rmask;
}

void clear_bits(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;
	if (loff == roff) {
		bitmap[loff] &= ~lmask | ~rmask;
		return;
	}
	bitmap[loff] &= ~lmask;
	memset(bitmap + loff + 1, 0, roff - loff - 1);
	if (rmask)
		bitmap[roff] &= ~rmask;
}

int all_set(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;
	if (loff == roff) {
		unsigned mask = lmask & rmask;
		return (bitmap[loff] & mask) == mask;
	}
	for (unsigned i = loff + 1; i < roff; i++)
		if (bitmap[i] != 0xff)
			return 0;
	return	(bitmap[loff] & lmask) == lmask &&
		(!rmask || (bitmap[roff] & rmask) == rmask);
}

static int bytebits(unsigned char c)
{
	unsigned count = 0;
	for (; c; c >>= 1)
		count += c & 1;
	return count;
}

block_t count_range(struct inode *inode, block_t start, block_t count)
{
	assert(!(start & 7));
	unsigned char ones[256];
	for (int i = 0; i < sizeof(ones); i++)
		ones[i] = bytebits(i);

	block_t limit = start + count;
	unsigned blocksize = 1 << inode->sb->blockbits;
	unsigned mapshift = inode->sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	block_t tail = (count + 7) >> 3, total = 0;

	for (unsigned block = start >> mapshift; block < blocks; block++) {
		//printf("count block %x/%x\n", block, blocks);
		struct buffer *buffer = blockread(mapping(inode), block);
		if (!buffer)
			return -1;
		unsigned bytes = blocksize - offset;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = buffer->data + offset, *top = p + bytes;
		while (p < top)
			total += ones[*p++];
		brelse(buffer);
		tail -= bytes;
		offset = 0;
	}
	return total;
}

block_t bitmap_dump(struct inode *inode, block_t start, block_t count)
{
	block_t limit = start + count;
	unsigned blocksize = 1 << inode->sb->blockbits;
	unsigned mapshift = inode->sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift, active = 0;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3, begin = -1;

	printf("%i bitmap blocks:\n", blocks);
	for (unsigned block = start >> mapshift; block < blocks; block++) {
		int ended = 0, any = 0;
		struct buffer *buffer = blockread(mapping(inode), block);
		if (!buffer)
			return -1;
		unsigned bytes = blocksize - offset;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = buffer->data + offset, *top = p + bytes;
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
				block_t found = i + (((void *)p - buffer->data) << 3) + (block << mapshift);
				if (begin < 0)
					begin = found;
				else {
					if ((begin >> mapshift) != block)
						printf("-%Lx ", (L)(found - 1));
					else if (begin == found - 1)
						printf("%Lx ", (L)begin);
					else
						printf("%Lx-%Lx ", (L)begin, (L)(found - 1));
					begin = -1;
					ended++;
				}
			}
		}
		active += !!any;
		brelse(buffer);
		tail -= bytes;
		offset = 0;
		if (begin >= 0)
			printf("%Lx-", (L)begin);
		if (any)
			printf("\n");
	}
	printf("(%i active)\n", active);
	return -1;
}

block_t balloc_extent_from_range(struct inode *inode, block_t start, unsigned count, unsigned blocks)
{
	trace("balloc %i blocks from [%Lx/%Lx]", blocks, (L)start, (L)count);
	block_t limit = start + count;
	unsigned blocksize = 1 << inode->sb->blockbits;
	unsigned mapshift = inode->sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned mapblocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3;
	for (unsigned mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		trace_off("search mapblock %x/%x", mapblock, mapblocks);
		struct buffer *buffer = blockread(mapping(inode), mapblock);
		if (!buffer)
			return -1;
		unsigned bytes = blocksize - offset, run = 0;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = buffer->data + offset, *top = p + bytes, c;
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
				block_t found = i + (((void *)p - buffer->data) << 3) + (mapblock << mapshift);
				if (found >= limit) {
					assert(mapblock == mapblocks - 1);
					goto final_partial_byte;
				}
				found -= run - 1;
				set_bits(buffer->data, found & mapmask, run);
				set_buffer_dirty(buffer);
				brelse(buffer);
				inode->sb->nextalloc = found + run;
				inode->sb->freeblocks -= run;
				//set_sb_dirty(sb);
				return found;
			}
		}
final_partial_byte:
		brelse(buffer);
		tail -= bytes;
		offset = 0;
	}
	return -1;
}

block_t balloc_from_range(struct inode *inode, block_t start, block_t count)
{
	return balloc_extent_from_range(inode, start, count, 1);
}

block_t balloc(SB)
{
	trace_off("balloc block at goal %Lx", (L)sb->nextalloc);
	block_t goal = sb->nextalloc, total = sb->volblocks, block;
	if ((block = balloc_from_range(sb->bitmap, goal, total - goal)) >= 0)
		goto found;
	if ((block = balloc_from_range(sb->bitmap, 0, goal)) >= 0)
		goto found;
	return -1;
found:
	trace("balloc -> [%Lx]", (L)block);
	return block;
}

block_t balloc_extent(SB, unsigned blocks)
{
	trace_off("balloc %x blocks at goal %Lx", blocks, (L)sb->nextalloc);
	block_t goal = sb->nextalloc, total = sb->volblocks, block;
	if ((block = balloc_extent_from_range(sb->bitmap, goal, total - goal, blocks)) >= 0)
		goto found;
	if ((block = balloc_extent_from_range(sb->bitmap, 0, goal, blocks)) >= 0)
		goto found;
	return -1;
found:
	printf("balloc extent -> [%Lx/%x]\n", (L)block, blocks);
	return block;
}

void bfree_extent(SB, block_t start, unsigned count)
{
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned mapblock = start >> mapshift;
	char *why = "could not read bitmap buffer";
	struct buffer *buffer = blockread(mapping(sb->bitmap), mapblock);
	printf("free <- [%Lx]\n", (L)start);
	if (!buffer)
		goto eek;
	if (!all_set(buffer->data, start &= mapmask, count))
		goto eeek;
	clear_bits(buffer->data, start, count);
	brelse_dirty(buffer);
	sb->freeblocks += count;
	//set_sb_dirty(sb);
	return;
eeek:
	why = "blocks already free";
	brelse(buffer);
eek:
	warn("extent 0x%Lx %s!\n", (L)start, why);
}

void bfree(SB, block_t block)
{
	bfree_extent(sb, block, 1);
}

#ifndef main
int main(int argc, char *argv[])
{
	if (1) {
		warn("---- test bitops ----");
		unsigned char bits[16];
		memset(bits, 0, sizeof(bits));
		set_bits(bits, 6, 20);
		set_bits(bits, 49, 16);
		set_bits(bits, 0x51, 2);
		hexdump(bits, sizeof(bits));
		/* should return true */
		printf("ones = %i\n", all_set(bits, 6, 20));
		printf("ones = %i\n", all_set(bits, 49, 16));
		printf("ones = %i\n", all_set(bits, 0x51, 2));
		/* should return false */
		printf("ones = %i\n", all_set(bits, 5, 20));
		printf("ones = %i\n", all_set(bits, 49, 17));
		printf("ones = %i\n", all_set(bits, 0x51, 3));
		clear_bits(bits, 6, 20);
		clear_bits(bits, 49, 16);
		clear_bits(bits, 0x51, 2);
		hexdump(bits, sizeof(bits)); // all zero now

		/* corner case */
		unsigned char *bitmap = malloc(7);
		set_bits(bitmap, 0, 7 * 8);
		int ret = all_set(bitmap, 0, 7 * 8);
		assert(ret);
		clear_bits(bitmap, 0, 7 * 8);
		free(bitmap);
	}
	struct dev *dev = &(struct dev){ .bits = 3 };
	map_t *map = new_map(dev, NULL);
	struct sb *sb = &(struct sb){ .super = { .volblocks = to_be_u64(150) }, .blockbits = dev->bits };
	struct inode *bitmap = &(struct inode){ .sb = sb, .map = map };
	sb->freeblocks = from_be_u64(sb->super.volblocks);
	sb->nextalloc = from_be_u64(sb->super.volblocks); // this should wrap around to zero
	sb->bitmap = bitmap;

	init_buffers(dev, 1 << 20);
	unsigned blocksize = 1 << dev->bits;
	unsigned dumpsize = blocksize > 16 ? 16 : blocksize;

	for (int block = 0; block < 10; block++) {
		struct buffer *buffer = blockget(map, block);
		memset(buffer->data, 0, blocksize);
		set_buffer_uptodate(buffer);
	}
	for (int i = 0; i < 12; i++) {
		block_t block = balloc_from_range(bitmap, 121, 10);
		printf("%Li\n", (L)block);
	}
	hexdump(blockget(map, 0)->data, dumpsize);
	hexdump(blockget(map, 1)->data, dumpsize);
	hexdump(blockget(map, 2)->data, dumpsize);

	sb->nextalloc++; // gap
	for (int i = 0; i < 1; i++)
		balloc(sb);
	sb->nextalloc++; // gap
	for (int i = 0; i < 10; i++)
		balloc(sb);
	hexdump(blockget(map, 0)->data, dumpsize);
	hexdump(blockget(map, 1)->data, dumpsize);
	hexdump(blockget(map, 2)->data, dumpsize);

	bitmap_dump(bitmap, 0, from_be_u64(sb->super.volblocks));
	printf("%Li used, %Li free\n", (L)count_range(bitmap, 0, from_be_u64(sb->super.volblocks)), (L)sb->freeblocks);
	bfree(sb, 0x7e);
	bfree(sb, 0x80);
	bitmap_dump(bitmap, 0, from_be_u64(sb->super.volblocks));
	return 0;
}
#endif
