/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#include "walk.c"

static void fsck_bnode(struct btree *btree, struct buffer_head *buffer,
		       int level, void *data)
{
}

static void fsck_dleaf_cb(struct btree *btree, struct buffer_head *leafbuf,
			  block_t index, block_t block, unsigned count,
			  void *data)
{
	struct inode *inode = data;
	printf("### inum %Lu, index %Lu, count %u\n",
	       tux_inode(inode)->inum, index, count);
}

static void fsck_dleaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	walk_dleaf(btree, leafbuf, fsck_dleaf_cb, data);
}

static struct walk_btree_ops fsck_dtree_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_dleaf,
};

static void fsck_ileaf_cb(struct buffer_head *leafbuf, int at,
			  struct inode *inode, void *data)
{
	struct btree *dtree = &tux_inode(inode)->btree;
	walk_btree(dtree, &fsck_dtree_ops, inode);
}

static void fsck_ileaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	walk_ileaf(btree, leafbuf, fsck_ileaf_cb, data);
}

static struct walk_btree_ops fsck_itable_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_ileaf,
};

static void fsck_oleaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
}

static struct walk_btree_ops fsck_otable_ops = {
	.bnode	= fsck_bnode,
	.leaf	= fsck_oleaf,
};

static int fsck_main(struct sb *sb)
{
	int err;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		return err;
	}

	walk_btree(itable_btree(sb), &fsck_itable_ops, NULL);
	walk_btree(otable_btree(sb), &fsck_otable_ops, NULL);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	return 0;
}
