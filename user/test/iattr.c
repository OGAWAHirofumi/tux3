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
	MODE_OWNER_ATTR = 6,
	CTIME_SIZE_ATTR = 7,
	DATA_BTREE_ATTR = 8,
	LINK_COUNT_ATTR = 9,
	MTIME_ATTR = 10,
};

unsigned atsize[16] = {
	[MODE_OWNER_ATTR] = 12,
	[CTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
	[MTIME_ATTR] = 6,
};

struct size_mtime_attr { u64 size:60, mtime:54; };
struct data_btree_attr { struct root root; };

struct iattrs {
	unsigned present;
	struct root root;
	u64 mtime, ctime, atime, isize;
	u32 mode, uid, gid, links;
} iattrs;

void *decode16(SB, void *attrs, unsigned *val)
{
	*val = be_to_u16(*(be_u16 *)attrs);
	return attrs + sizeof(u16);
}

void *decode32(SB, void *attrs, unsigned *val)
{
	*val = be_to_u32(*(be_u32 *)attrs);
	return attrs + sizeof(u32);
}

void *decode64(SB, void *attrs, u64 *val)
{
	*val = be_to_u64(*(be_u64 *)attrs);
	return attrs + sizeof(u64);
}

void *decode48(SB, void *attrs, u64 *val)
{
	unsigned part1, part2;
	attrs = decode16(sb, attrs, &part1);
	attrs = decode32(sb, attrs, &part2);
	*val = (u64)part1 << 32 | part2;
	return attrs;
}

int decode_attrs(SB, void *attrs, unsigned size, struct iattrs *iattrs)
{
	printf("decode %u attr bytes\n", size);
	void *limit = attrs + size;
	u64 v64;
	while (attrs < limit - 1) {
		unsigned head;
		attrs = decode16(sb, attrs, &head);
		unsigned version = head & 0xfff, kind = head >> 12;
		if (version != sb->version) {
			attrs += atsize[kind];
			continue;
		}
		iattrs->present |= 1 << kind;
		switch (kind) {
		case MODE_OWNER_ATTR:
			attrs = decode32(sb, attrs, &iattrs->mode);
			attrs = decode32(sb, attrs, &iattrs->uid);
			attrs = decode32(sb, attrs, &iattrs->gid);
			//printf("mode = %x uid = %x, gid = %x\n", iattrs->mode, iattrs->uid, iattrs->gid);
			break;
		case CTIME_SIZE_ATTR:
			attrs = decode48(sb, attrs, &iattrs->ctime);
			attrs = decode64(sb, attrs, &iattrs->isize);
			//printf("ctime = %Lx, isize = %Lx\n", (L)iattrs->ctime, (L)iattrs->isize);
			break;
		case MTIME_ATTR:
			attrs = decode48(sb, attrs, &iattrs->mtime);
			//printf("mtime = %Lx\n", (L)iattrs->mtime);
			break;
		case DATA_BTREE_ATTR:
			attrs = decode64(sb, attrs, &v64);
			iattrs->root = (struct root){ .block = v64 & (-1ULL >> 16), .depth = v64 >> 48 };
			//printf("btree block = %Lx, depth = %u\n", (L)iattrs->root.block, iattrs->root.depth);
			break;
		case LINK_COUNT_ATTR:
			attrs = decode32(sb, attrs, &iattrs->links);
			//printf("links = %u\n", iattrs->links);
			break;
		default:
			warn("unknown attribute kind %i", kind);
			return -EINVAL;
		}
	}
	return 0;
}

void dump_attrs(SB, struct iattrs *iattrs)
{
	printf("present = %x\n", iattrs->present);
	for (int which = 0; which < 32; which++) {
		if (!(iattrs->present & (1 << which)))
			continue;
		switch (which) {
		case MODE_OWNER_ATTR:
			printf("mode %x uid %x gid %x ", iattrs->mode, iattrs->uid, iattrs->gid);
			break;
		case CTIME_SIZE_ATTR:
			printf("ctime %Lx isize %Lx ", (L)iattrs->ctime, (L)iattrs->isize);
			break;
		case MTIME_ATTR:
			printf("mtime %Lx ", (L)iattrs->mtime);
			break;
		case DATA_BTREE_ATTR:
			printf("btree %Lx/%u ", (L)iattrs->root.block, iattrs->root.depth);
			break;
		case LINK_COUNT_ATTR:
			printf("links %u ", iattrs->links);
			break;
		default:
			printf("<%i>? ", which);
			break;
		}
	}
	printf("\n");
}

void *encode16(SB, void *attrs, unsigned val)
{
	*(be_u16 *)attrs = u16_to_be(val);
	return attrs + sizeof(u16);
}

void *encode32(SB, void *attrs, unsigned val)
{
	*(be_u32 *)attrs = u32_to_be(val);
	return attrs + sizeof(u32);
}

void *encode64(SB, void *attrs, u64 val)
{
	*(be_u64 *)attrs = u64_to_be(val);
	return attrs + sizeof(u64);
}

void *encode48(SB, void *attrs, u64 val)
{
	attrs = encode16(sb, attrs, val >> 32);
	return encode32(sb, attrs, val);
}

void *encode_kind(SB, void *attrs, unsigned kind)
{
	return encode16(sb, attrs, (kind << 12) | sb->version);
}

void *encode_owner(SB, void *attrs, u32 mode, u32 uid, u32 gid)
{
	attrs = encode_kind(sb, attrs, MODE_OWNER_ATTR);
	attrs = encode32(sb, attrs, mode);
	attrs = encode32(sb, attrs, uid);
	return encode32(sb, attrs, gid);
}

void *encode_csize(SB, void *attrs, u64 ctime, u64 isize)
{
	attrs = encode_kind(sb, attrs, CTIME_SIZE_ATTR);
	attrs = encode48(sb, attrs, ctime);
	return encode64(sb, attrs, isize);
}

void *encode_mtime(SB, void *attrs, u64 mtime)
{
	attrs = encode_kind(sb, attrs, MTIME_ATTR);
	return encode48(sb, attrs, mtime);
}

void *encode_btree(SB, void *attrs, struct root *root)
{
	attrs = encode_kind(sb, attrs, DATA_BTREE_ATTR);
	return encode64(sb, attrs, ((u64)root->depth) << 48 | root->block);
}

void *encode_links(SB, void *attrs, u32 links)
{
	attrs = encode_kind(sb, attrs, LINK_COUNT_ATTR);
	return encode32(sb, attrs, links);
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
	u8 alist[] = { DATA_BTREE_ATTR, CTIME_SIZE_ATTR, MODE_OWNER_ATTR, LINK_COUNT_ATTR, MTIME_ATTR };
	printf("need %i attr bytes\n", howbig(alist, sizeof(alist)));
	char attrbase[1000] = { };
	char *attrs = attrbase;
	attrs = encode_owner(sb, attrs, 0x666, 0x12121212, 0x34343434);
	attrs = encode_btree(sb, attrs, &(struct root){ .block = 0xcaba1f00d, .depth = 3 });
	attrs = encode_csize(sb, attrs, 0xdec0debead, 0x123456789);
	attrs = encode_links(sb, attrs, 999);
//sb->version = 9;
	attrs = encode_mtime(sb, attrs, 0xdeadfaced00d);
	struct iattrs iattrs = { };
	decode_attrs(sb, attrbase, attrs - attrbase, &iattrs);
	dump_attrs(sb, &iattrs);
	return 0;
}
#endif
#endif
