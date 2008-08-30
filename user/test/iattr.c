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

inline void *decode16(void *attrs, unsigned *val)
{
	*val = be_to_u16(*(be_u16 *)attrs);
	return attrs + sizeof(u16);
}

inline void *decode32(void *attrs, unsigned *val)
{
	*val = be_to_u32(*(be_u32 *)attrs);
	return attrs + sizeof(u32);
}

inline void *decode64(void *attrs, u64 *val)
{
	*val = be_to_u64(*(be_u64 *)attrs);
	return attrs + sizeof(u64);
}

inline void *decode48(void *attrs, u64 *val)
{
	unsigned part1, part2;
	attrs = decode16(attrs, &part1);
	attrs = decode32(attrs, &part2);
	*val = (u64)part1 << 32 | part2;
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
			inode->btree = (struct btree){ .sb = sb,
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
			printf("mode 0%o uid %x gid %x ", inode->i_mode, inode->i_uid, inode->i_gid);
			break;
		case CTIME_SIZE_ATTR:
			printf("ctime %Lx isize %Lx ", (L)inode->i_ctime, (L)inode->i_size);
			break;
		case MTIME_ATTR:
			printf("mtime %Lx ", (L)inode->i_mtime);
			break;
		case DATA_BTREE_ATTR:
			printf("root %Lx:%u ", (L)inode->btree.root.block, inode->btree.root.depth);
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

inline void *encode16(void *attrs, unsigned val)
{
	*(be_u16 *)attrs = u16_to_be(val);
	return attrs + sizeof(u16);
}

inline void *encode32(void *attrs, unsigned val)
{
	*(be_u32 *)attrs = u32_to_be(val);
	return attrs + sizeof(u32);
}

inline void *encode64(void *attrs, u64 val)
{
	*(be_u64 *)attrs = u64_to_be(val);
	return attrs + sizeof(u64);
}

inline void *encode48(void *attrs, u64 val)
{
	attrs = encode16(attrs, val >> 32);
	return encode32(attrs, val);
}

inline void *encode_kind(void *attrs, unsigned kind, unsigned version)
{
	return encode16(attrs, (kind << 12) | version);
}

inline void *encode_owner(void *attrs, u32 mode, u32 uid, u32 gid)
{
	attrs = encode32(attrs, mode);
	attrs = encode32(attrs, uid);
	return encode32(attrs, gid);
}

inline void *encode_csize(void *attrs, u64 ctime, u64 isize)
{
	attrs = encode48(attrs, ctime);
	return encode64(attrs, isize);
}

inline void *encode_mtime(void *attrs, u64 mtime)
{
	return encode48(attrs, mtime);
}

inline void *encode_btree(void *attrs, struct root *root)
{
	return encode64(attrs, ((u64)root->depth) << 48 | root->block);
}

inline void *encode_links(void *attrs, u32 links)
{
	return encode32(attrs, links);
}

unsigned howbig(unsigned bits)
{
	unsigned need = 0;
	for (int bit = 0; bit < 32; bit++)
		if ((bits & (1 << bit)))
			need += atsize[bit] + 2;
	return need;
}


#ifndef main
#ifndef iattr_included_from_ileaf
int main(int argc, char *argv[])
{
	SB = &(struct sb){ .version = 0 };
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	printf("need %i attr bytes\n", howbig(abits));
	char attrbase[1000] = { };
	char *attrs = attrbase;
	attrs = encode_kind(attrs, MODE_OWNER_ATTR, sb->version);
	attrs = encode_owner(attrs, 0x666, 0x12121212, 0x34343434);
	attrs = encode_kind(attrs, DATA_BTREE_ATTR, sb->version);
	attrs = encode_btree(attrs, &(struct root){ .block = 0xcaba1f00d, .depth = 3 });
	attrs = encode_kind(attrs, CTIME_SIZE_ATTR, sb->version);
	attrs = encode_csize(attrs, 0xdec0debead, 0x123456789);
	attrs = encode_kind(attrs, LINK_COUNT_ATTR, sb->version);
	attrs = encode_links(attrs, 999);
//sb->version = 9;
	attrs = encode_kind(attrs, MTIME_ATTR, sb->version);
	attrs = encode_mtime(attrs, 0xdeadfaced00d);
	struct inode inode = { };
	printf("decode %ti attr bytes\n", attrs - attrbase);
	decode_attrs(sb, attrbase, attrs - attrbase, &inode);
	dump_attrs(sb, &inode);
	return 0;
}
#endif
#endif
