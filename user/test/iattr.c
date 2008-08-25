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
	CTIME_OWNER_ATTR = 6,
	MTIME_SIZE_ATTR = 7,
	DATA_BTREE_ATTR = 9,
	LINK_COUNT_ATTR = 8,
};

unsigned atsize[16] = {
	[CTIME_OWNER_ATTR] = 18,
	[MTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
};

struct size_mtime_attr { u64 size:60, mtime:54; };
struct data_btree_attr { struct root root; };

struct iattrs {
	struct root root;
	u64 mtime, ctime, isize;
	u32 mode, uid, gid, links;
} iattrs;

char *decode16(SB, void *attr, unsigned *val)
{
	*val = be_to_u16(*(be_u16 *)attr);
	return attr + sizeof(u16);
}

char *decode32(SB, char *attr, unsigned *val)
{
	*val = be_to_u32(*(be_u32 *)attr);
	return attr + sizeof(u32);
}

char *decode64(SB, char *attr, u64 *val)
{
	*val = be_to_u64(*(be_u64 *)attr);
	return attr + sizeof(u64);
}

char *decode48(SB, char *attr, u64 *val)
{
	unsigned part1, part2;
	attr = decode16(sb, attr, &part1);
	attr = decode32(sb, attr, &part2);
	*val = (u64)part1 << 32 | part2;
	return attr;
}

int decode_attrs(SB, void *attr, unsigned size)
{
	printf("decode %u attr bytes\n", size);
	struct iattrs iattrs = { };
	void *limit = attr + size;
	u64 v64;
	while (attr < limit - 1) {
		unsigned head, kind, version;
		attr = decode16(sb, attr, &head);
		if ((version = head & 0xfff))
			continue;
		switch (kind = (head >> 12)) {
		case CTIME_OWNER_ATTR:
			attr = decode48(sb, attr, &iattrs.ctime);
			attr = decode32(sb, attr, &iattrs.mode);
			attr = decode32(sb, attr, &iattrs.uid);
			attr = decode32(sb, attr, &iattrs.gid);
			//printf("ctime = %Lx, mode = %x\n", (L)iattrs.ctime, iattrs.mode);
			//printf("uid = %x, gid = %x\n", iattrs.uid, iattrs.gid);
			break;
		case MTIME_SIZE_ATTR:
			attr = decode64(sb, attr - 2, &v64);
			attr = decode64(sb, attr, &iattrs.isize);
			iattrs.mtime = v64 & (-1ULL >> 16);
			//printf("mtime = %Lx, isize = %Lx\n", (L)iattrs.mtime, (L)iattrs.isize);
			break;
		case DATA_BTREE_ATTR:
			attr = decode64(sb, attr, &v64);
			iattrs.root = (struct root){
				.block = v64 & (-1ULL >> 16),
				.depth = v64 >> 48 };
			//printf("btree block = %Lx, depth = %u\n", (L)iattrs.root.block, iattrs.root.depth);
			break;
		case LINK_COUNT_ATTR:
			attr = decode32(sb, attr, &iattrs.links);
			//printf("links = %u\n", iattrs.links);
			break;
		default:
			warn("unknown attribute kind %i", kind);
			return 0;
		}
	}
	return 0;
}

int dump_attrs(SB, void *attr, unsigned size)
{
	struct iattrs iattrs = { };
	void *limit = attr + size;
	u64 v64;
	while (attr < limit - 1) {
		unsigned head, kind, version;
		attr = decode16(sb, attr, &head);
		if ((version = head & 0xfff))
			continue;
		switch (kind = (head >> 12)) {
		case CTIME_OWNER_ATTR:
			attr = decode48(sb, attr, &iattrs.ctime);
			attr = decode32(sb, attr, &iattrs.mode);
			attr = decode32(sb, attr, &iattrs.uid);
			attr = decode32(sb, attr, &iattrs.gid);
			printf("ctime %Lx mode %x ", (L)iattrs.ctime, iattrs.mode);
			printf("uid %x gid %x ", iattrs.uid, iattrs.gid);
			break;
		case MTIME_SIZE_ATTR:
			attr = decode64(sb, attr - 2, &v64);
			attr = decode64(sb, attr, &iattrs.isize);
			iattrs.mtime = v64 & (-1ULL >> 16);
			printf("mtime %Lx isize %Lx ", (L)iattrs.mtime, (L)iattrs.isize);
			break;
		case DATA_BTREE_ATTR:
			attr = decode64(sb, attr, &v64);
			iattrs.root = (struct root){
				.block = v64 & (-1ULL >> 16),
				.depth = v64 >> 48 };
			printf("btree (block %Lx depth %u) ", (L)iattrs.root.block, iattrs.root.depth);
			break;
		case LINK_COUNT_ATTR:
			attr = decode32(sb, attr, &iattrs.links);
			printf("links %u ", iattrs.links);
			break;
		default:
			printf("<?%i?> ", kind);
			break;
		}
	}
	printf("(%u bytes)\n", size);
	return 0;
}

char *encode16(SB, char *attr, unsigned val)
{
	*(be_u16 *)attr = u16_to_be(val);
	return attr + sizeof(u16);
}

char *encode32(SB, char *attr, unsigned val)
{
	*(be_u32 *)attr = u32_to_be(val);
	return attr + sizeof(u32);
}

char *encode64(SB, char *attr, u64 val)
{
	*(be_u64 *)attr = u64_to_be(val);
	return attr + sizeof(u64);
}

char *encode48(SB, char *attr, u64 val)
{
	attr = encode16(sb, attr, val >> 32);
	return encode32(sb, attr, val);
}

char *encode_kind(SB, char *attr, unsigned kind)
{
	return encode16(sb, attr, (kind << 12) | sb->version);
}

char *encode_btree(SB, char *attr, struct root *root)
{
	attr = encode_kind(sb, attr, DATA_BTREE_ATTR);
	return encode64(sb, attr, ((u64)root->depth) << 48 | root->block);
}

char *encode_msize(SB, char *attr, u64 mtime, u64 isize)
{
	attr = encode_kind(sb, attr, MTIME_SIZE_ATTR);
	attr = encode48(sb, attr, mtime);
	return encode64(sb, attr, isize);
}

char *encode_owner(SB, char *attr, u64 ctime, u32 mode, u32 uid, u32 gid)
{
	attr = encode_kind(sb, attr, CTIME_OWNER_ATTR);
	attr = encode48(sb, attr, ctime);
	attr = encode32(sb, attr, mode);
	attr = encode32(sb, attr, uid);
	return encode32(sb, attr, gid);
}

char *encode_links(SB, char *attr, u32 links)
{
	attr = encode_kind(sb, attr, LINK_COUNT_ATTR);
	return encode32(sb, attr, links);
}

unsigned howbig(u8 kind[], unsigned howmany)
{
	unsigned need = 0;
	for (int i = 0; i < howmany; i++)
		need += 2 + atsize[kind[i]];
	return need;
}

#ifndef main
#ifndef iattr_included_from_ileaf
int main(int argc, char *argv[])
{
	SB = &(struct sb){ .version = 0 };
	char iattrs[1000] = { };
	u8 alist[] = { DATA_BTREE_ATTR, MTIME_SIZE_ATTR, CTIME_OWNER_ATTR, LINK_COUNT_ATTR };
	memset(iattrs, 0, sizeof(iattrs));
	printf("need %i attr bytes\n", howbig(alist, sizeof(alist)));
	char *attr = iattrs;
	attr = encode_owner(sb, attr, 0xdeadfaced00d, 0x666, 0x12121212, 0x34343434);
	attr = encode_btree(sb, attr, &(struct root){ .block = 0xcaba1f00d, .depth = 3 });
	attr = encode_msize(sb, attr, 0xdec0debead, 0x123456789);
	attr = encode_links(sb, attr, 999);
	decode_attrs(sb, iattrs, attr - iattrs);
	dump_attrs(sb, iattrs, attr - iattrs);
	return 0;
}
#endif
#endif
