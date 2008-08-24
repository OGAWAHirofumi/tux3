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
#include "buffer.h"
#include "tux3.h"

static int bytebits(unsigned char c)
{
	unsigned count = 0;
	for (; c; c >>= 1)
		count += c & 1;
	return count;
}

block_t count_range(struct inode *inode, block_t start, block_t count)
{
	assert(!start & 7);
	unsigned char ones[256];
	for (int i = 0; i < sizeof(ones); i++)
		ones[i] = bytebits(i);

	block_t limit = start + count;
	unsigned blocksize = 1 << inode->map->dev->bits;
	unsigned mapshift = inode->map->dev->bits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	block_t tail = (count + 7) >> 3, total = 0;

	for (unsigned block = start >> mapshift; block < blocks; block++) {
		//printf("count block %x/%x\n", block, blocks);
		struct buffer *buffer = bread(inode->map, block);
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
	unsigned blocksize = 1 << inode->map->dev->bits;
	unsigned mapshift = inode->map->dev->bits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift, active = 0;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3, begin = -1;

	printf("%i bitmap blocks:\n", blocks);
	for (unsigned block = start >> mapshift; block < blocks; block++) {
		int ended = 0, any = 0;
		struct buffer *buffer = bread(inode->map, block);
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

block_t balloc_range(struct inode *inode, block_t start, block_t count)
{
	block_t limit = start + count;
	unsigned blocksize = 1 << inode->map->dev->bits;
	unsigned mapshift = inode->map->dev->bits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned blocks = (limit + mapmask) >> mapshift;
	unsigned offset = (start & mapmask) >> 3;
	unsigned startbit = start & 7;
	block_t tail = (count + startbit + 7) >> 3;

	for (unsigned block = start >> mapshift; block < blocks; block++) {
		//printf("search block %x/%x\n", block, blocks);
		struct buffer *buffer = bread(inode->map, block);
		if (!buffer)
			return -1;
		unsigned bytes = blocksize - offset;
		if (bytes > tail)
			bytes = tail;
		unsigned char *p = buffer->data + offset, *top = p + bytes, c;
		for (; p < top; p++, startbit = 0) {
			if ((c = *p) == 0xff)
				continue;
			for (int i = startbit, mask = 1 << startbit; i < 8; i++, mask <<= 1) {
				if ((c & mask))
					continue;
				block_t found = i + (((void *)p - buffer->data) << 3) + (block << mapshift);
				if (found >= limit) {
					assert(block == blocks - 1);
					goto final_partial_byte;
				}
				set_bit(buffer->data, found & mapmask);
				set_buffer_dirty(buffer);
				brelse(buffer);
				inode->sb->nextalloc = found + 1;
				inode->sb->freeblocks--;
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

block_t balloc(SB)
{
	block_t goal = sb->nextalloc, total = sb->image.blocks, block;
	if ((block = balloc_range(sb->bitmap, goal, total - goal)) >= 0)
		goto found;
	if ((block = balloc_range(sb->bitmap, 0, goal)) >= 0)
		goto found;
	return -1;
found:
	printf("balloc -> [%Lx]\n", (L)block);
	return block;
}

void bfree(SB, block_t block)
{
	unsigned mapshift = sb->bitmap->map->dev->bits + 3;
	unsigned mapmask = (1 << mapshift) - 1;
	unsigned mapblock = block >> mapshift;
	char *why = "free failed";
	struct buffer *buffer = bread(sb->bitmap->map, mapblock);
	printf("free <- [%Lx]\n", (L)block);
	if (!buffer)
		goto eek;
	if (!get_bit(buffer->data, block & mapmask))
		goto eek2;
	reset_bit(buffer->data, block & mapmask);
	brelse_dirty(buffer);
	sb->freeblocks++;
	//set_sb_dirty(sb);
	return;
eek2:
	why = "already free";
	brelse(buffer);
eek:
	warn("block 0x%Lx %s!\n", (L)block, why);
}

#ifndef main
int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 3 };
	struct map *map = new_map(dev, NULL);
	struct sb *sb = &(struct sb){ .image = { .blocks = 150 } };
	struct inode *bitmap = &(struct inode){ .sb = sb, .map = map };
	sb->freeblocks = sb->image.blocks;
	sb->nextalloc = sb->image.blocks; // this should wrap around to zero
	sb->bitmap = bitmap;

	init_buffers(dev, 1 << 20);
	unsigned blocksize = 1 << dev->bits;
	unsigned dumpsize = blocksize > 16 ? 16 : blocksize;

	for (int block = 0; block < 10; block++) {
		struct buffer *buffer = getblk(map, block);
		memset(buffer->data, 0, blocksize);
		set_buffer_uptodate(buffer);
	}
	for (int i = 0; i < 12; i++) {
		block_t block = balloc_range(bitmap, 121, 10);
		printf("%Li\n", block);
	}
	hexdump(getblk(map, 0)->data, dumpsize);
	hexdump(getblk(map, 1)->data, dumpsize);
	hexdump(getblk(map, 2)->data, dumpsize);

	sb->nextalloc++; // gap
	for (int i = 0; i < 1; i++)
		balloc(sb);
	sb->nextalloc++; // gap
	for (int i = 0; i < 10; i++)
		balloc(sb);
	hexdump(getblk(map, 0)->data, dumpsize);
	hexdump(getblk(map, 1)->data, dumpsize);
	hexdump(getblk(map, 2)->data, dumpsize);

	bitmap_dump(bitmap, 0, sb->image.blocks);
	printf("%Li used, %Li free\n", count_range(bitmap, 0, sb->image.blocks), sb->freeblocks);
	bfree(sb, 0x7e);
	bfree(sb, 0x80);
	bitmap_dump(bitmap, 0, sb->image.blocks);
	return 0;
}
#endif
