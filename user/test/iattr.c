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

int decode_attrs(void *base, unsigned size )
{
	struct iattrs iattrs = { };
	unsigned char *attr = base, *limit = base + size;
	unsigned kind;
	u64 v64; // u32 v32; u16 v16;
	for (; attr < limit - 1; attr += atsize[kind]) {
		unsigned c = *attr++, version = ((c & 0xf) << 8) | *attr++;
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

int encode_btree(void *base, struct root *root)
{
	return 0;
}

#ifndef main
int main(int argc, char *argv[])
{
	char iattrs[] = {
		DATA_BTREE_ATTR << 4, 0,
			0, 1, 0, 0, 0, 0, 0x12, 0x34,
		MTIME_SIZE_ATTR << 4, 0,
			0xc0, 0xde, 0xba, 0xbe, 0xfa, 0xce,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x23,
	};
	load_inode(iattrs, sizeof(iattrs));
	return 0;
}
#endif
