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

enum {
	CTIME_OWNER_ATTR = 7,
	MTIME_SIZE_ATTR = 8,
	DATA_BTREE_ATTR = 9,
};

unsigned atsize[16] = {
	[MTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
};

struct size_mtime_attr { u64 size:60, mtime:54; };
struct data_btree_attr { struct root root; };

struct iattrs {
	struct root root;
	u64 mtime, isize;
} iattrs;

int decode_attrs(void *base, unsigned size)
{
	printf("decode %u attr bytes\n", size);
	struct iattrs iattrs = { };
	unsigned char *attr = base, *limit = base + size;
	unsigned kind;
	u64 v64; // u32 v32; u16 v16;
	for (; attr < limit - 1; attr += atsize[kind]) {
		unsigned c = *attr++, version = ((c & 0xf) << 8) | *attr++;
		kind = c >> 4;
		if (version)
			continue;
		switch ((kind = c >> 4)) {
		case MTIME_SIZE_ATTR:
			iattrs.mtime = be_to_u64(*(u64 *)(attr - 2)) & (-1ULL >> 16);
			iattrs.isize = be_to_u64(*(u64 *)(attr + 6));
			printf("mtime = %Lx, isize = %Lx\n", (L)iattrs.mtime, iattrs.isize);
			break;
		case DATA_BTREE_ATTR:
			v64 = be_to_u64(*(u64 *)attr);
			iattrs.root = (struct root){
				.block = v64 & (-1ULL >> 16),
				.depth = v64 >> 48 };
			printf("btree block = %Lx, depth = %u\n", (L)iattrs.root.block, iattrs.root.depth);
			break;
		default:
			goto unknown;
		}
	}
	return 0;
unknown:
	error("unknown attribute kind %i", kind);
	return 0;
}

char *encode_atkind(SB, char *attr, unsigned kind)
{
	*(be_u16 *)attr = u16_to_be((kind << 12) | sb->version);
	return attr + 2;
}

char *encode_six(SB, char *attr, u64 val)
{
	*(be_u16 *)attr = u16_to_be(val >> 32);
	*(be_u32 *)(attr + 2) = u32_to_be(val);
	return attr + 6;
}

char *encode_eight(SB, char *attr, u64 val)
{
	*(be_u64 *)attr = u64_to_be(val);
	return attr + 8;
}

char *encode_btree(SB, char *attr, struct root *root)
{
	attr = encode_atkind(sb, attr, DATA_BTREE_ATTR);
	return encode_eight(sb, attr, ((u64)root->depth) << 48 | root->block);
}

char *encode_msize(SB, char *attr, u64 isize, u64 mtime)
{
	attr = encode_atkind(sb, attr, MTIME_SIZE_ATTR);
	attr = encode_six(sb, attr, mtime);
	return encode_eight(sb, attr, isize);
}

unsigned howbig(u8 kind[], unsigned howmany)
{
	unsigned need = 0;
	for (int i = 0; i < howmany; i++)
		need += 2 + atsize[kind[i]];
	return need;
}

#ifndef main
int main(int argc, char *argv[])
{
	SB = &(struct sb){ .version = 0 };
	char iattrs[1000] = { };
	memset(iattrs, 0, sizeof(iattrs));
	printf("need %i bytes\n", howbig((u8[]){ DATA_BTREE_ATTR, MTIME_SIZE_ATTR }, 2));
	char *attr = iattrs;
	attr = encode_msize(sb, attr, 0x123456789, 0xbeefdec0de);
	attr = encode_btree(sb, attr, &(struct root){ .block = 0xbadbabeface, .depth = 3 });
	decode_attrs(iattrs, attr - iattrs);
	return 0;
}
#endif
