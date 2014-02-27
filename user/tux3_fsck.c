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
#define FSCK_COUNTMAP_ERROR	101
#define FSCK_INODE_ERROR	102

struct fsck_shadow {
	const char *name;
	int fd;
	int size;

	void *mapptr;
	size_t mapsize;
	loff_t mappos;
};

struct fsck_context {
	int error;

	/* Shadow bitmap */
	struct fsck_shadow bitmap_s;
	/* Shadow countmap */
	struct fsck_shadow countmap_s;

	block_t freeblocks;
	block_t freeinodes;
};

/*
 * Shadow file operations
 */

static void fsck_init_shadow(struct fsck_shadow *shadow, size_t size,
			     int delete)
{
	int fd;

	/* Setup shadow bitmap */
	fd = open(shadow->name, O_CREAT | O_RDWR | O_EXCL, 0644);
	if (fd < 0)
		strerror_exit(1, errno, "couldn't create %s", shadow->name);

	if (ftruncate(fd, size) < 0)
		strerror_exit(1, errno, "ftruncate");

	if (delete)
		unlink(shadow->name);

	shadow->fd	= fd;
	shadow->size	= size;
	shadow->mapptr	= NULL;
	shadow->mappos	= -1;
	shadow->mapsize	= 0;
}

static void fsck_destroy_shadow(struct fsck_shadow *shadow)
{
	if (shadow->mapptr)
		munmap(shadow->mapptr, shadow->mapsize);
	close(shadow->fd);
}

/* Map shadow file for each 256MB region */
static void *fsck_shadow_read(struct sb *sb, struct fsck_shadow *shadow,
			      block_t index)
{
#define MAP_BITS	28
#define MAP_SIZE	((loff_t)1 << MAP_BITS)
#define MAP_MASK	(MAP_SIZE - 1)
	loff_t pos = index << sb->blockbits;
	loff_t mappos = pos & ~MAP_MASK;
	unsigned mapoffset = pos & MAP_MASK;
	void *ptr = shadow->mapptr;

	if (mappos != shadow->mappos) {
		size_t mapsize;

		if (shadow->mapptr)
			munmap(shadow->mapptr, shadow->mapsize);

		mapsize = min(shadow->size - mappos, MAP_SIZE);
		ptr = mmap(NULL, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED,
			   shadow->fd, mappos);
		if (ptr == MAP_FAILED)
			strerror_exit(1, errno, "mmap");

		shadow->mapptr		= ptr;
		shadow->mappos		= mappos;
		shadow->mapsize	= mapsize;
	}

	return ptr + mapoffset;
}

struct fsck_cmp_shadow_data {
	struct fsck_context *context;
	void (*compare)(struct fsck_context *, struct btree *,
			struct buffer_head *, struct buffer_head *,
			block_t, block_t);
};

/* Compare shadow file with extent */
static void
fsck_cmp_shadow_extent(struct btree *btree, struct buffer_head *parent,
		       block_t index, block_t block, unsigned count, void *data)
{
	struct inode *inode = btree_inode(btree);
	struct fsck_cmp_shadow_data *cmp_data = data;
	struct fsck_context *context = cmp_data->context;
	block_t limit = index + count;

	while (index < limit) {
		struct buffer_head *buffer;

		buffer = blockread(mapping(inode), index);
		assert(buffer);

		cmp_data->compare(context, btree, parent, buffer, index, block);

		blockput(buffer);
		index++;
	}
}

static struct walk_dleaf_ops fsck_cmp_shadow_dleaf_ops = {
	.extent = fsck_cmp_shadow_extent,
};

static void fsck_cmp_shadow_dleaf(struct btree *btree,
				  struct buffer_head *buffer, void *data)
{
	walk_dleaf(btree, buffer, &fsck_cmp_shadow_dleaf_ops, data);
}

static struct walk_btree_ops walk_cmp_shadow_dtree_ops = {
	.leaf	= fsck_cmp_shadow_dleaf,
};

/*
 * Fsck context
 */

static void fsck_init_context(struct sb *sb, struct fsck_context *context,
			      int delete)
{
#define SHIFT_ALIGN(x, b)	(((x) + (1 << (b)) - 1) >> (b))

	size_t bitmap_size = SHIFT_ALIGN(sb->volblocks, 3);
	size_t countmap_size = SHIFT_ALIGN(sb->volblocks, sb->groupbits) << 1;

	fsck_init_shadow(&context->bitmap_s, bitmap_size, delete);
	fsck_init_shadow(&context->countmap_s, countmap_size, delete);

	context->freeblocks = sb->volblocks;
	context->freeinodes = MAX_INODES - TUX_NORMAL_INO;
}

static void fsck_destroy_context(struct fsck_context *context)
{
	fsck_destroy_shadow(&context->countmap_s);
	fsck_destroy_shadow(&context->bitmap_s);
}

/*
 * Modify shadow files
 */

static void shadow_countmap_modify(struct sb *sb, struct fsck_context *context,
				   block_t start, unsigned count, int set)
{
	unsigned groupsize = 1 << sb->groupbits;
	unsigned groupmask = groupsize - 1;

	while (count) {
		block_t group = start >> sb->groupbits;
		block_t index = group >> (sb->blockbits - 1);
		unsigned offset = group & (sb->blockmask >> 1);
		unsigned grouplen = (~start & groupmask) + 1;
		int len = min(grouplen, count);
		int diff = set ? len : -len;
		__be16 *p;

		p = fsck_shadow_read(sb, &context->countmap_s, index);
		be16_add_cpu(p + offset, diff);

		start += len;
		count -= len;
	}
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

	shadow_countmap_modify(sb, context, start, count, set);

	trace("start %Lu, count %u, set %d", start, count, set);

	for (mapblock = start >> mapshift; mapblock < mapblocks; mapblock++) {
		void *p = fsck_shadow_read(sb, &context->bitmap_s, mapblock);
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

/* Compare countmap with shadow countmap */
static void
fsck_cmp_countmap(struct fsck_context *context, struct btree *btree,
		  struct buffer_head *parent, struct buffer_head *buffer,
		  block_t index, block_t block)
{
	struct sb *sb = btree->sb;
	block_t group;
	unsigned long *cnt, *shw;
	int i;

	cnt = bufdata(buffer);
	shw = fsck_shadow_read(sb, &context->countmap_s, index);

	for (i = 0; i < sb->blocksize / sizeof(*cnt); i++) {
		unsigned long diff = shw[i] ^ cnt[i];
		int nr = sizeof(*shw) / sizeof(__be16);
		__be16 *s, *c;
		int j;

		if (!diff)
			continue;

		group = (index << (sb->groupbits - 1)) + (i * nr);
		s = (__be16 *)&shw[i];
		c = (__be16 *)&cnt[i];
		for (j = 0; j < nr; j++) {
			if (s[j] == c[j])
				continue;

			tux3_err(sb,
				 "diff: group %Lu, shadow %u, countmap %u",
				 group + j,
				 be16_to_cpu(s[j]), be16_to_cpu(c[j]));

			context->error = FSCK_COUNTMAP_ERROR;
		}
	}
}

static void fsck_check_countmap(struct sb *sb, struct fsck_context *context)
{
	struct fsck_cmp_shadow_data cmp_data = {
		.context = context,
		.compare = fsck_cmp_countmap,
	};
	struct inode *countmap = sb->countmap;
	struct btree *dtree = &tux_inode(countmap)->btree;

	walk_btree(dtree, &walk_cmp_shadow_dtree_ops, &cmp_data);
}

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
fsck_cmp_bitmap(struct fsck_context *context, struct btree *btree,
		struct buffer_head *parent, struct buffer_head *buffer,
		block_t index, block_t block)
{
	struct sb *sb = btree->sb;
	unsigned mapshift = sb->blockbits + 3;
	block_t start = index << mapshift;
	unsigned long *bmp, *shw;
	int i;

	bmp = bufdata(buffer);
	shw = fsck_shadow_read(sb, &context->bitmap_s, index);

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
}

static void fsck_check_bitmap(struct sb *sb, struct fsck_context *context)
{
	struct fsck_cmp_shadow_data cmp_data = {
		.context = context,
		.compare = fsck_cmp_bitmap,
	};
	struct inode *bitmap = sb->bitmap;
	struct btree *dtree = &tux_inode(bitmap)->btree;

	walk_btree(dtree, &walk_cmp_shadow_dtree_ops, &cmp_data);

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
		.bitmap_s = {
			.name = "shadow_bitmap",
		},
		.countmap_s = {
			.name = "shadow_countmap",
		},
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
	fsck_check_countmap(sb, &context);
	fsck_check_inodes(sb, &context);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	fsck_destroy_context(&context);

	if (context.error)
		exit(context.error);

	return 0;
}
