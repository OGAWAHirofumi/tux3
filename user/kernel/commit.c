/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

static void unpack_sb(struct sb *sb, struct disksuper *super)
{
	sb->blockbits = from_be_u16(super->blockbits);
	sb->blocksize = 1 << sb->blockbits;
	sb->blockmask = (1 << sb->blockbits) - 1;
	/* FIXME: those should be initialized based on blocksize. */
	sb->entries_per_node = 20;
	sb->max_inodes_per_block = 64;
//	sb->version;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->volblocks = from_be_u64(super->volblocks);
	sb->freeblocks = from_be_u64(super->freeblocks);
	sb->nextalloc = from_be_u64(super->nextalloc);
	sb->atomgen = from_be_u32(super->atomgen);
	sb->freeatom = from_be_u32(super->freeatom);
	sb->dictsize = from_be_u64(super->dictsize);
}

static void pack_sb(struct sb *sb, struct disksuper *super)
{
	super->blockbits = to_be_u16(sb->blockbits);
	super->volblocks = to_be_u64(sb->volblocks);
	super->freeblocks = to_be_u64(sb->freeblocks); // probably does not belong here
	super->nextalloc = to_be_u64(sb->nextalloc); // probably does not belong here
	super->atomgen = to_be_u32(sb->atomgen); // probably does not belong here
	super->freeatom = to_be_u32(sb->freeatom); // probably does not belong here
	super->dictsize = to_be_u64(sb->dictsize); // probably does not belong here
	super->iroot = to_be_u64(pack_root(&itable_btree(sb)->root));
}

int load_sb(struct sb *sb)
{
	int err = devio(READ, sb_dev(sb), SB_LOC, &sb->super, SB_LEN);
	if (err)
		return err;
	if (memcmp(sb->super.magic, (char[])SB_MAGIC, sizeof(sb->super.magic)))
		return -EINVAL;
	unpack_sb(sb, &sb->super);
	trace("blocksize %u, blockbits %u, blockmask %08x",
	      sb->blocksize, sb->blockbits, sb->blockmask);
	trace("volblocks %Lu, freeblocks %Lu, nextalloc %Lu",
	      (L)sb->volblocks, (L)sb->freeblocks, (L)sb->nextalloc);
	trace("freeatom %u, atomgen %u", sb->freeatom, sb->atomgen);
	return 0;
}

int save_sb(struct sb *sb)
{
	pack_sb(sb, &sb->super);
	return devio(WRITE, sb_dev(sb), SB_LOC, &sb->super, SB_LEN);
}

int load_itable(struct sb *sb)
{
	u64 iroot_val = from_be_u64(sb->super.iroot);
	init_btree(itable_btree(sb), sb, unpack_root(iroot_val), &itable_ops);
	return 0;
}
