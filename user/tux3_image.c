/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#include "walk.c"

/*
 * 0 - minimum
 * 1 - include derollup blocks
 * 2 - include freed blocks, bug still pointed by log (may including data)
 */
static int opt_verbose;
/* include data blocks */
static int opt_data;

struct image_context {
	struct sb *sb;
	int fd;
};

static void image_init_context(struct sb *sb, struct image_context *context,
			       const char *output)
{
	int fd;

	fd = open(output, O_CREAT | O_WRONLY | O_EXCL, 0600);
	if (fd < 0)
		strerror_exit(1, errno, "couldn't create %s", output);

	if (ftruncate(fd, sb->volblocks << sb->blockbits) < 0)
		strerror_exit(1, errno, "ftruncate");

	context->sb = sb;
	context->fd = fd;
}

static void image_destroy_context(struct image_context *context)
{
	close(context->fd);
}

static void image_write(struct image_context *context,
			block_t block, unsigned count)
{
	static char buf[1024 * 1024];
	struct sb *sb = context->sb;
	loff_t pos = block << sb->blockbits;
	ssize_t ret;

	while (count--) {
		ret = pread(sb->dev->fd, buf, sb->blocksize, pos);
		if (ret != sb->blocksize)
			strerror_exit(1, errno, "pread %zd", ret);

		ret = pwrite(context->fd, buf, sb->blocksize, pos);
		if (ret != sb->blocksize)
			strerror_exit(1, errno, "pwrite %zd", ret);

		pos += sb->blocksize;
	}
}

static void image_write_buffer(struct image_context *context,
			       struct buffer_head *buffer, block_t block)
{
	if (!buffer_dirty(buffer))
		image_write(context, block, 1);
}

/*
 * Walk filesystem
 */

static void image_bnode(struct btree *btree, struct buffer_head *buffer,
			int level, void *data)
{
	struct image_context *context = data;
	image_write_buffer(context, buffer, bufindex(buffer));
}

static void image_dleaf_cb(struct btree *btree, struct buffer_head *leafbuf,
			   block_t index, block_t block, unsigned count,
			   void *data)
{
	struct image_context *context = data;
	image_write(context, block, count);
}

static void __image_dleaf(struct btree *btree, struct buffer_head *leafbuf,
			  void *data, int write_data)
{
	struct image_context *context = data;
	image_write_buffer(context, leafbuf, bufindex(leafbuf));

	if (write_data)
		walk_dleaf(btree, leafbuf, image_dleaf_cb, data);
}

static void image_dleaf(struct btree *btree, struct buffer_head *leafbuf,
			void *data)
{
	__image_dleaf(btree, leafbuf, data, 1);
}

static void image_dleaf_without_data(struct btree *btree,
				     struct buffer_head *leafbuf, void *data)
{
	__image_dleaf(btree, leafbuf, data, 0);
}

static struct walk_btree_ops image_dtree_ops = {
	.bnode	= image_bnode,
	.leaf	= image_dleaf,
};

static struct walk_btree_ops image_dtree_without_data_ops = {
	.bnode	= image_bnode,
	.leaf	= image_dleaf_without_data,
};

static void image_ileaf_cb(struct buffer_head *leafbuf, int at,
			   struct inode *inode, void *data)
{
	struct btree *dtree = &tux_inode(inode)->btree;

	if (!opt_data && S_ISREG(inode->i_mode))
		walk_btree(dtree, &image_dtree_without_data_ops, data);
	else
		walk_btree(dtree, &image_dtree_ops, data);
}

static void image_ileaf(struct btree *btree, struct buffer_head *leafbuf,
			void *data)
{
	struct image_context *context = data;
	image_write_buffer(context, leafbuf, bufindex(leafbuf));

	walk_ileaf(btree, leafbuf, image_ileaf_cb, data);
}

static struct walk_btree_ops image_itree_ops = {
	.bnode	= image_bnode,
	.leaf	= image_ileaf,
};

static void image_oleaf(struct btree *btree, struct buffer_head *leafbuf,
			void *data)
{
	struct image_context *context = data;
	image_write_buffer(context, leafbuf, bufindex(leafbuf));
}

static struct walk_btree_ops image_otree_ops = {
	.bnode	= image_bnode,
	.leaf	= image_oleaf,
};

static void image_log_pre(struct sb *sb, struct buffer_head *buffer,
			  unsigned logcount, int obsolete, void *data)
{
	struct image_context *context = data;
	image_write_buffer(context, buffer, bufindex(buffer));
}

static void image_log(struct sb *sb, struct buffer_head *buffer,
		      u8 code, u8 *p, unsigned len, int obsolete, void *data)
{
	struct image_context *context = data;

	if (obsolete && opt_verbose < 2)
		return;

	switch (code) {
	case LOG_BFREE:
	case LOG_BFREE_RELOG:
		if (opt_verbose < 2)
			break;
		/* FALLTHRU */
	case LOG_BFREE_ON_ROLLUP: {
		u32 count;
		u64 block;
		p = decode32(p, &count);
		p = decode48(p, &block);
		if (opt_verbose) {
			trace("obsolete %d: [%s] block %Lu, count %u",
			      obsolete, log_name[code], block, count);
			image_write(context, block, count);
		}
		break;
	}
	case LOG_LEAF_REDIRECT:
		if (opt_verbose < 2)
			break;
		/* FALLTHRU */
	case LOG_BNODE_REDIRECT: {
		u64 old, new;
		p = decode48(p, &old);
		p = decode48(p, &new);
		trace("obsolete %d: [%s] old %Lu",
		      obsolete, log_name[code], old);
		image_write(context, old, 1);
		break;
	}
	case LOG_LEAF_FREE:
		if (opt_verbose < 2)
			break;
		/* FALLTHRU */
	case LOG_BNODE_FREE: {
		u64 block;
		p = decode48(p, &block);
		if (opt_verbose) {
			trace("obsolete %d: [%s] block %Lu",
			      obsolete, log_name[code], block);
			image_write(context, block, 1);
		}
		break;
	}
	}
}

static struct walk_logchain_ops image_logchain_ops = {
	.pre	= image_log_pre,
	.log	= image_log,
};

/* Copy reserved region to image */
static void image_copy_superblock(struct sb *sb, struct image_context *context)
{
	/* Always 8K regardless of blocksize */
	int count = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);

	/* Copy blocks from 0 to 8KB */
	image_write(context, 0, count);
}

static int image_main(struct sb *sb, const char *name)
{
	struct image_context context;
	int err;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		return err;
	}

	image_init_context(sb, &context, name);

	image_copy_superblock(sb, &context);
	walk_logchain(sb, &image_logchain_ops, &context);
	walk_btree(itree_btree(sb), &image_itree_ops, &context);
	walk_btree(otree_btree(sb), &image_otree_ops, &context);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	image_destroy_context(&context);

	return 0;
}
