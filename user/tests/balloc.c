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
#include "test.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/balloc.c"

static int bitmap_all_test(struct sb *sb, block_t start, unsigned count,
			   int (*test)(uint8_t *, unsigned, unsigned))
{
	struct inode *bitmap = sb->bitmap;
	block_t start_block = start >> (3 + sb->blockbits);
	block_t end_block = (((start + count + 7) >> 3) + sb->blocksize - 1) >> sb->blockbits;
	int ret = 1;

	for (block_t block = start_block; block < end_block; block++) {
		loff_t block_start = (loff_t)(block << sb->blockbits) << 3;
		loff_t block_count = (loff_t)sb->blocksize << 3;

		struct buffer_head *buf = blockget(bitmap->map, block);
		loff_t start_off, end_off, checkcnt;

		start_off = max_t(loff_t, start - block_start, 0);
		end_off = min(start + count - block_start, block_count);
		checkcnt = end_off - start_off;

		ret = test(bufdata(buf), start_off, checkcnt);

		blockput(buf);
		if (!ret)
			break;
	}
	return ret;
}

static int bitmap_all_set(struct sb *sb, block_t start, unsigned count)
{
	return bitmap_all_test(sb, start, count, all_set);
}

static int bitmap_all_clear(struct sb *sb, block_t start, unsigned count)
{
	return bitmap_all_test(sb, start, count, all_clear);
}

/* cleanup bitmap of main() */
static void clean_main(struct sb *sb)
{
	invalidate_buffers(sb->bitmap->map);
	free_map(sb->bitmap->map);
}

/* Tests bits set/clear/test functions */
static void test01(struct sb *sb, block_t blocks)
{
	warn("---- test bitops ----");
	unsigned char bits[16];
	memset(bits, 0, sizeof(bits));
	/* set some bits */
	set_bits(bits, 6, 20);
	set_bits(bits, 49, 16);
	set_bits(bits, 0x51, 2);
	/* test set bits */
	test_assert(all_set(bits, 6, 20));
	test_assert(all_set(bits, 49, 16));
	test_assert(all_set(bits, 0x51, 2));
	/* test clear bits */
	test_assert(all_clear(bits, 6, 20) == 0);
	test_assert(all_clear(bits, 49, 16) == 0);
	test_assert(all_clear(bits, 0x51, 2) == 0);
	/* should return false */
	test_assert(all_set(bits, 5, 20) == 0);
	test_assert(all_set(bits, 49, 17) == 0);
	test_assert(all_set(bits, 0x51, 3) == 0);
	test_assert(all_clear(bits, 5, 20) == 0);
	test_assert(all_clear(bits, 49, 17) == 0);
	test_assert(all_clear(bits, 0x51, 3) == 0);

	/* all zero now */
	clear_bits(bits, 6, 20);
	clear_bits(bits, 49, 16);
	clear_bits(bits, 0x51, 2);
	test_assert(all_clear(bits, 0, 8 * sizeof(bits)));
	test_assert(all_clear(bits, 6, 20));
	test_assert(all_clear(bits, 49, 16));
	test_assert(all_clear(bits, 0x51, 2));
	test_assert(all_set(bits, 6, 20) == 0);
	test_assert(all_set(bits, 49, 16) == 0);
	test_assert(all_set(bits, 0x51, 2) == 0);

	/* Corner case */
	unsigned char *bitmap = malloc(7);
	set_bits(bitmap, 0, 7 * 8);
	test_assert(all_set(bitmap, 0, 7 * 8));
	test_assert(all_clear(bitmap, 0, 7 * 8) == 0);
	clear_bits(bitmap, 0, 7 * 8);
	test_assert(all_clear(bitmap, 0, 7 * 8));
	test_assert(all_set(bitmap, 0, 7 * 8) == 0);
	free(bitmap);

	clean_main(sb);
}

static void test02(struct sb *sb, block_t blocks)
{
	/* Allocate specific range */
	block_t start = 121;
	unsigned count = 10;
	for (int i = 0; i < count + 2; i++) {
		block_t block = balloc_from_range(sb, start, count, 1);
		if (i < count)
			test_assert(block == start + i);
		else
			test_assert(block == -1);
	}
	/* Check bitmap */
	test_assert(bitmap_all_set(sb, start, count));
	test_assert(bitmap_all_clear(sb, 0, start));
	loff_t cnt = ((blocks << sb->blockbits) << 3) - (start + count);
	test_assert(bitmap_all_clear(sb, start + count, cnt));

	for (int i = 0; i < count; i++) {
		int err = bfree(sb, start + i, 1);
		if (i < count)
			test_assert(!err);
		else
			test_assert(err);
	}
	test_assert(bitmap_all_clear(sb, 0, (blocks << sb->blockbits) << 3));

	clean_main(sb);
}

static void test03(struct sb *sb, block_t blocks)
{
	block_t block;

	/* nextalloc point last bit, but can't allocate 2 bits. So,
	 * this should wrap around to zero */
	sb->nextalloc = sb->volblocks - 1;
	test_assert(balloc(sb, 2, &block) == 0);
	test_assert(bitmap_all_set(sb, 0, 2));
	test_assert(bitmap_all_clear(sb, 2, sb->volblocks));

	test_assert(bfree(sb, block, 2) == 0);
	test_assert(bitmap_all_clear(sb, 0, sb->volblocks));

	clean_main(sb);
}

static void test04(struct sb *sb, block_t blocks)
{
	block_t block, start;

	/* nextalloc point last bit, this should wrap around to zero */
	start = sb->nextalloc = sb->volblocks - 1;
	for (int i = 0; i < 2; i++) {
		test_assert(balloc(sb, 1, &block) == 0);
		test_assert(block == (start + i) % sb->volblocks);
	}
	test_assert(bitmap_all_set(sb, 0, 1));
	test_assert(bitmap_all_clear(sb, 1, sb->volblocks - 2));
	test_assert(bitmap_all_set(sb, sb->volblocks - 1, 1));

	test_assert(bfree(sb, start + 0, 1) == 0);
	test_assert(bfree(sb, 0, 1) == 0);
	test_assert(bitmap_all_clear(sb, 0, sb->volblocks));

	clean_main(sb);
}

static void test05(struct sb *sb, block_t blocks)
{
	block_t block;
	block_t bits = 1 << (3 + sb->blockbits);

	for (int i = 0; i < 2; i++) {
		/* Alloc blocks on a bitmap page */
		test_assert(balloc(sb, bits, &block) == 0);
		test_assert(block == i * bits);
		test_assert(bitmap_all_set(sb, i * bits, bits));
	}
	test_assert(bitmap_all_set(sb, 0, 2 * bits));

	for (int i = 0; i < 2; i++) {
		/* Free blocks on a bitmap page */
		test_assert(bfree(sb, i * bits, bits) == 0);
		test_assert(bitmap_all_clear(sb, i * bits, bits));
	}
	test_assert(bitmap_all_clear(sb, 0, 2 * bits));

	clean_main(sb);
}

#if 0 /* Maybe, we should support this */
static void test06(struct sb *sb, block_t blocks)
{
	block_t block;

	/* Alloc blocks on multiple bitmap data pages */
	test_assert(balloc(sb, sb->volblocks, &block) == 0);
	test_assert(block == 0);
	test_assert(bitmap_all_set(sb, 0, sb->volblocks));

	/* Free blocks on multiple bitmap data pages */
	test_assert(bfree(sb, 0, sb->volblocks) == 0);
	test_assert(bitmap_all_clear(sb, 0, sb->volblocks));

	clean_main(sb);
}
#endif

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 3 };
	init_buffers(dev, 1 << 20, 1);

	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	test_init(argv[0]);

	struct inode *bitmap = rapid_open_inode(sb, NULL, 0);
	sb->bitmap = bitmap;

	/* Setup buffers for bitmap */
	block_t blocks = 10;
	for (int block = 0; block < blocks; block++) {
		struct buffer_head *buffer = blockget(bitmap->map, block);
		memset(bufdata(buffer), 0, sb->blocksize);
		set_buffer_clean(buffer);
		blockput(buffer);
	}

	if (test_start("test01"))
		test01(sb, blocks);
	test_end();

	if (test_start("test02"))
		test02(sb, blocks);
	test_end();

	if (test_start("test03"))
		test03(sb, blocks);
	test_end();

	if (test_start("test04"))
		test04(sb, blocks);
	test_end();

	if (test_start("test05"))
		test05(sb, blocks);
	test_end();

#if 0 /* Maybe, we should support this */
	if (test_start("test06"))
		test06(sb, blocks);
	test_end();
#endif

	clean_main(sb);

	return test_failures();
}
