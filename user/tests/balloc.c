/*
 * Block allocation
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/balloc.c"

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
	init_buffers(dev, 1 << 20, 0);

	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);
	sb->nextalloc = sb->volblocks; // this should wrap around to zero

	struct inode *bitmap = rapid_open_inode(sb, NULL, 0);
	sb->bitmap = bitmap;

	unsigned blocksize = sb->blocksize;
	unsigned dumpsize = blocksize > 16 ? 16 : blocksize;

	for (int block = 0; block < 10; block++) {
		struct buffer_head *buffer = blockget(bitmap->map, block);
		memset(bufdata(buffer), 0, blocksize);
		set_buffer_clean(buffer);
	}
	for (int i = 0; i < 12; i++) {
		block_t block = balloc_from_range(sb, 121, 10, 1);
		printf("%Li\n", (L)block);
	}
	hexdump(bufdata(blockget(bitmap->map, 0)), dumpsize);
	hexdump(bufdata(blockget(bitmap->map, 1)), dumpsize);
	hexdump(bufdata(blockget(bitmap->map, 2)), dumpsize);

	block_t block;
	sb->nextalloc++; // gap
	for (int i = 0; i < 1; i++)
		balloc(sb, 1, &block);
	sb->nextalloc++; // gap
	for (int i = 0; i < 10; i++)
		balloc(sb, 1, &block);
	hexdump(bufdata(blockget(bitmap->map, 0)), dumpsize);
	hexdump(bufdata(blockget(bitmap->map, 1)), dumpsize);
	hexdump(bufdata(blockget(bitmap->map, 2)), dumpsize);

	bitmap_dump(bitmap, 0, sb->volblocks);
	printf("%Li used, %Li free\n", (L)count_range(bitmap, 0, sb->volblocks), (L)sb->freeblocks);
	bfree(sb, 0x7e, 1);
	bfree(sb, 0x80, 1);
	bitmap_dump(bitmap, 0, sb->volblocks);
	exit(0);
}
