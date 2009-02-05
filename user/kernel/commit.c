/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

int unpack_sb(struct sb *sb, struct disksuper *super, struct root *iroot)
{
	u64 iroot_val = from_be_u64(super->iroot);
	if (memcmp(super->magic, (char[])SB_MAGIC, sizeof(super->magic)))
		return -EINVAL;
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

	*iroot = unpack_root(iroot_val);

	return 0;
}

void pack_sb(struct sb *sb, struct disksuper *super)
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

int tux_load_sb(struct sb *sb)
{
	struct root iroot;
	int err = devio(READ, sb_dev(sb), SB_LOC, &sb->super, SB_LEN);
	if (err)
		return err;
	err = unpack_sb(sb, &sb->super, &iroot);
	if (err)
		return err;
	trace("depth %Lu, block %Lu", (L)iroot.depth, (L)iroot.block);
	trace("blocksize %u, blockbits %u, blockmask %08x",
	       sb->blocksize, sb->blockbits, sb->blockmask);
	trace("volblocks %Lu, freeblocks %Lu, nextalloc %Lu",
	       sb->volblocks, sb->freeblocks, sb->nextalloc);
	trace("freeatom %u, atomgen %u", sb->freeatom, sb->atomgen);
	init_btree(itable_btree(sb), sb, iroot, &itable_ops);
	return 0;
}

int tux_save_sb(struct sb *sb)
{
	pack_sb(sb, &sb->super);
	return devio(WRITE, sb_dev(sb), SB_LOC, &sb->super, SB_LEN);
}

