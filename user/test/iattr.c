/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "hexdump.c"
#include "tux3.h"

unsigned atsize[16] = {
	[MODE_OWNER_ATTR] = 12,
	[CTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
	[MTIME_ATTR] = 6,
};

unsigned howbig(unsigned bits)
{
	unsigned need = 0;
	for (int bit = 0; bit < 32; bit++)
		if ((bits & (1 << bit)))
			need += atsize[bit] + 2;
	return need;
}

void *encode_attrs(SB, void *attrs, unsigned size, struct inode *inode)
{
	//printf("encode %u attr bytes\n", size);
	void *limit = attrs + size - 3;
	for (int kind = 0; kind < 32; kind++) {
		if (!(inode->present & (1 << kind)))
			continue;
		if (attrs >= limit)
			break;
		attrs = encode16(attrs, (kind << 12) | sb->version);
		switch (kind) {
		case MODE_OWNER_ATTR:
			attrs = encode32(attrs, inode->i_mode);
			attrs = encode32(attrs, inode->i_uid);
			attrs = encode32(attrs, inode->i_gid);
			break;
		case CTIME_SIZE_ATTR:
			attrs = encode48(attrs, inode->i_ctime);
			attrs = encode64(attrs, inode->i_size);
			break;
		case MTIME_ATTR:
			attrs = encode48(attrs, inode->i_mtime);
			break;
		case DATA_BTREE_ATTR:;
			struct root *root = &inode->btree.root;
			attrs = encode64(attrs, ((u64)root->depth << 48) | root->block);
			break;
		case LINK_COUNT_ATTR:
			attrs = encode32(attrs, inode->i_links);
			break;
		}
	}
	return attrs;
}

int decode_attrs(SB, void *attrs, unsigned size, struct inode *inode)
{
	//printf("decode %u attr bytes\n", size);
	u64 v64;
	void *limit = attrs + size;
	while (attrs < limit - 1) {
		unsigned head;
		attrs = decode16(attrs, &head);
		unsigned version = head & 0xfff, kind = head >> 12;
		if (version != sb->version) {
			attrs += atsize[kind];
			continue;
		}
		switch (kind) {
		case MODE_OWNER_ATTR:
			attrs = decode32(attrs, &inode->i_mode);
			attrs = decode32(attrs, &inode->i_uid);
			attrs = decode32(attrs, &inode->i_gid);
			break;
		case CTIME_SIZE_ATTR:
			attrs = decode48(attrs, &inode->i_ctime);
			attrs = decode64(attrs, &inode->i_size);
			break;
		case MTIME_ATTR:
			attrs = decode48(attrs, &inode->i_mtime);
			break;
		case DATA_BTREE_ATTR:
			attrs = decode64(attrs, &v64);
			inode->btree = (struct btree){ .sb = sb, .entries_per_leaf = 64, // !!! should depend on blocksize
#ifdef main
				.ops = &dtree_ops,
#endif
				.root = { .block = v64 & (-1ULL >> 16), .depth = v64 >> 48 } };
			break;
		case LINK_COUNT_ATTR:
			attrs = decode32(attrs, &inode->i_links);
			break;
		default:
			return -EINVAL;
		}
		inode->present |= 1 << kind;
	}
	return 0;
}

void dump_attrs(SB, struct inode *inode)
{
	//printf("present = %x\n", inode->present);
	for (int which = 0; which < 32; which++) {
		if (!(inode->present & (1 << which)))
			continue;
		switch (which) {
		case MODE_OWNER_ATTR:
			printf("mode 0%.6o uid %x gid %x ", inode->i_mode, inode->i_uid, inode->i_gid);
			break;
		case DATA_BTREE_ATTR:
			printf("root %Lx:%u ", (L)inode->btree.root.block, inode->btree.root.depth);
			break;
		case CTIME_SIZE_ATTR:
			printf("ctime %Lx size %Lx ", (L)inode->i_ctime, (L)inode->i_size);
			break;
		case MTIME_ATTR:
			printf("mtime %Lx ", (L)inode->i_mtime);
			break;
		case LINK_COUNT_ATTR:
			printf("links %u ", inode->i_links);
			break;
		default:
			printf("<%i>? ", which);
			break;
		}
	}
	printf("\n");
}

#ifndef main
#ifndef iattr_included_from_ileaf
int main(int argc, char *argv[])
{
	SB = &(struct sb){ .version = 0 };
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	printf("need %i attr bytes\n", howbig(abits));
	struct inode inode = {
		.present = abits, .i_mode = 0x666, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00d, .depth = 3 } },
		.i_size = 0x123456789, .i_ctime = 0xdec0debead, .i_mtime = 0xbadfaced00d };
	char attrbase[1000] = { };
	char *attrs = attrbase;
	printf("decode %ti attr bytes\n", attrs - attrbase);
	decode_attrs(sb, attrbase, attrs - attrbase, &inode);
	dump_attrs(sb, &inode);
	return 0;
}
#endif
#endif
