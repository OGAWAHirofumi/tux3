/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"
#include <sys/mman.h>

#include "walk.c"

#define FSCK_BITMAP_ERROR	100
#define FSCK_INODE_ERROR	101

struct fsck_context {
	int error;

	/* Shadow bitmap */
	const char *shadow_name;
	int shadow_fd;
	int shadow_size;

	void *mapptr;
	size_t mapsize;
	loff_t mappos;

	block_t freeblocks;
	block_t freeinodes;
};

/*
 * Shadow bitmap operations
 */

static void fsck_init_context(struct sb *sb, struct fsck_context *context,
			      int delete)
{
	size_t size = (sb->volblocks + 7) >> 3;
	int fd;

	/* Setup shadow bitmap */
	fd = open(context->shadow_name, O_CREAT | O_RDWR | O_EXCL, 0644);
	if (fd < 0)
		strerror_exit(1, errno, "couldn't create %s",
			      context->shadow_name);

	if (ftruncate(fd, size) < 0)
		strerror_exit(1, errno, "ftruncate");

	if (delete)
		unlink(context->shadow_name);

	context->shadow_fd	= fd;
	context->shadow_size	= size;
	context->mapptr		= NULL;
	context->mappos		= -1;
	context->mapsize	= 0;

	context->freeblocks	= sb->volblocks;
	context->freeinodes = MAX_INODES - TUX_NORMAL_INO;
}

static void fsck_destroy_context(struct fsck_context *context)
{
	if (context->mapptr)
		munmap(context->mapptr, context->mapsize);
	close(context->shadow_fd);
}

/* Map shadow bitmap for each 256MB region */
static void *shadow_bitmap_read(struct sb *sb, struct fsck_context *context,
				block_t index)
{
#define MAP_BITS	28
#define MAP_SIZE	((loff_t)1 << MAP_BITS)
#define MAP_MASK	(MAP_SIZE - 1)
	loff_t pos = index << sb->blockbits;
	loff_t mappos = pos & ~MAP_MASK;
	unsigned mapoffset = pos & MAP_MASK;
	void *ptr = context->mapptr;

	if (mappos != context->mappos) {
		size_t mapsize;

		if (context->mapptr)
			munmap(context->mapptr, context->mapsize);

		mapsize = min(context->shadow_size - mappos, MAP_SIZE);
		ptr = mmap(NULL, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED,
			   context->shadow_fd, mappos);
		if (ptr == MAP_FAILED)
			strerror_exit(1, errno, "mmap");

		context->mapptr		= ptr;
		context->mappos		= mappos;
		context->mapsize	= mapsize;
	}

	return ptr + mapoffset;
}

static void shadow_bitmap_modify(struct sb *sb, struct fsck_context *context,
				 block_t start, unsigned count, int set)
{
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapsize = 1 << mapshift;
	unsigned mapmask = mapsize - 1;
	unsigned mapoffset = start & mapmask;
	block_t mapblock, mapblocks = (start + count + mapmask) >> mapshift;
	int (*test)(u8 *, unsigned, unsigned) = set ? all_clear : all_set;
	void (*modify)(u8 *, unsigned, unsigned) = set ? set_bits : clear_bits;

	trace("start %Lu, count %u, set %d", start, count, set);

	for (mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		void *p = shadow_bitmap_read(sb, context, mapblock);
		unsigned len = min(mapsize - mapoffset, count);

		if (!test(p, mapoffset, len)) {
			error_exit("%s: start 0x%Lx, count %x",
				   set ? "already allocated" : "double free",
				   start, len);
		}

		modify(p, mapoffset, len);

		if (set)
			context->freeblocks -= len;
		else
			context->freeblocks += len;

		mapoffset = 0;
		start += len;
		count -= len;
	}
}

/*
 * Checking
 */

static inline unsigned long le_long_to_cpu(const unsigned long y)
{
#if BITS_PER_LONG == 64
	return (unsigned long) le64_to_cpu((__force __le64) y);
#elif BITS_PER_LONG == 32
	return (unsigned long) le32_to_cpu((__force __le32) y);
#else
#error BITS_PER_LONG not defined
#endif
}

/* Compare bitmap with shadow bitmap */
static void
fsck_cmp_bitmap_extent(struct btree *btree, struct buffer_head *parent,
		       block_t index, block_t block, unsigned count,
		       void *data)
{
	struct fsck_context *context = data;
	struct sb *sb = btree->sb;
	struct inode *bitmap = sb->bitmap;
	unsigned mapshift = sb->blockbits + 3;
	unsigned mapsize = 1 << mapshift;
	block_t start = index << mapshift;
	block_t limit = index + count;

	while (index < limit) {
		struct buffer_head *buffer;
		unsigned long *bmp, *shw;
		int i;

		buffer = blockread(mapping(bitmap), index);
		assert(buffer);

		bmp = bufdata(buffer);
		shw = shadow_bitmap_read(sb, context, index);

		for (i = 0; i < sb->blocksize / sizeof(*bmp); i++) {
			unsigned long diff = shw[i] ^ bmp[i];
			unsigned long s, b;
			int j;

			if (!diff)
				continue;

			s = le_long_to_cpu(shw[i]);
			b = le_long_to_cpu(bmp[i]);
			diff = s ^ b;
			for (j = 0; j < BITS_PER_LONG; j++) {
				if (!(diff & (1UL << j)))
					continue;

				tux3_err(sb,
					"diff: block %Lu, shadow %u, bitmap %u",
					start + (i * BITS_PER_LONG) + j,
					!!(s & (1UL << j)),
					!!(b & (1UL << j)));

				context->error = FSCK_BITMAP_ERROR;
			}
		}

		blockput(buffer);

		index++;
		start += mapsize;
	}
}

static struct walk_dleaf_ops fsck_cmp_bitmap_dleaf_ops = {
	.extent = fsck_cmp_bitmap_extent,
};

static void fsck_cmp_bitmap_dleaf(struct btree *btree,
				  struct buffer_head *buffer, void *data)
{
	walk_dleaf(btree, buffer, &fsck_cmp_bitmap_dleaf_ops, data);
}

static struct walk_btree_ops walk_cmp_bitmap_dtree_ops = {
	.leaf	= fsck_cmp_bitmap_dleaf,
};

static void fsck_check_bitmap(struct sb *sb, struct fsck_context *context)
{
	struct inode *bitmap = sb->bitmap;
	struct btree *dtree = &tux_inode(bitmap)->btree;

	walk_btree(dtree, &walk_cmp_bitmap_dtree_ops, context);

	if (context->freeblocks != sb->freeblocks) {
		tux3_err(sb, "shadow freeblocks %Lu, freeblocks %Lu",
		     context->freeblocks, sb->freeblocks);
		context->error = FSCK_BITMAP_ERROR;
	}
}

static void fsck_check_inodes(struct sb *sb, struct fsck_context *context)
{
	if (context->freeinodes != sb->freeinodes) {
		tux3_err(sb, "shadow freeinodes %Lu, freeinodes %Lu",
		     context->freeinodes, sb->freeinodes);
		context->error = FSCK_INODE_ERROR;
	}
}

/*
 * Walk filesystem
 */

static void fsck_dleaf_extent(struct btree *btree, struct buffer_head *leafbuf,
			      block_t index, block_t block, unsigned count,
			      void *data)
{
	struct fsck_context *context = data;
	shadow_bitmap_modify(btree->sb, context, block, count, 1);
}

static struct walk_dleaf_ops fsck_dleaf_ops = {
	.extent = fsck_dleaf_extent,
};

static void fsck_bnode(struct btree *btree, struct buffer_head *buffer,
		       int level, void *data)
{
	struct fsck_context *context = data;
	shadow_bitmap_modify(btree->sb, context, bufindex(buffer), 1, 1);
}

static void fsck_dleaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	struct fsck_context *context = data;
	shadow_bitmap_modify(btree->sb, context, bufindex(leafbuf), 1, 1);

	walk_dleaf(btree, leafbuf, &fsck_dleaf_ops, data);
}

static struct walk_btree_ops fsck_dtree_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_dleaf,
};

static void fsck_ileaf_cb(struct buffer_head *leafbuf, int at,
			  struct inode *inode, void *data)
{
	struct fsck_context *context = data;
	struct btree *dtree = &tux_inode(inode)->btree;

	if (tux_inode(inode)->inum >= TUX_NORMAL_INO)
		context->freeinodes--;

	walk_btree(dtree, &fsck_dtree_ops, data);
}

static void fsck_ileaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	struct fsck_context *context = data;
	shadow_bitmap_modify(btree->sb, context, bufindex(leafbuf), 1, 1);

	walk_ileaf(btree, leafbuf, fsck_ileaf_cb, data);
}

static struct walk_btree_ops fsck_itree_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_ileaf,
};

static void fsck_oleaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	struct fsck_context *context = data;
	shadow_bitmap_modify(btree->sb, context, bufindex(leafbuf), 1, 1);
}

static struct walk_btree_ops fsck_otree_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_oleaf,
};

/* Mark dfree_unify to shadow bitmap */
static struct fsck_context *fsck_unstash_context;
static int fsck_unstash_mark(struct sb *sb, u64 val)
{
	block_t block = val & ~(-1ULL << 48);
	unsigned count = val >> 48;
	shadow_bitmap_modify(sb, fsck_unstash_context, block, count, 1);
	return 0;
}

/* Mark reserved region to shadow bitmap */
static void fsck_mark_superblock(struct sb *sb, struct fsck_context *context)
{
	/* Always 8K regardless of blocksize */
	int count = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);

	/* Reserve blocks from 0 to 8KB */
	shadow_bitmap_modify(sb, context, 0, count, 1);
}

static int fsck_main(struct sb *sb)
{
	struct fsck_context context = {
		.shadow_name = "shadow_bitmap",
	};
	int err;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		return err;
	}

	fsck_init_context(sb, &context, 1);

	fsck_mark_superblock(sb, &context);

	fsck_unstash_context = &context;
	stash_walk(sb, &sb->deunify, fsck_unstash_mark);

	walk_btree(itree_btree(sb), &fsck_itree_ops, &context);
	walk_btree(otree_btree(sb), &fsck_otree_ops, &context);

	fsck_check_bitmap(sb, &context);
	fsck_check_inodes(sb, &context);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	fsck_destroy_context(&context);

	if (context.error)
		exit(context.error);

	return 0;
}
