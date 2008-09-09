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

/*
 * Variable size attribute format:
 *
 *    immediate data: kind+version:16, bytes:16, data[bytes]
 *    immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
 */

static unsigned atsize[MAX_ATTRS] = {
	[MODE_OWNER_ATTR] = 12,
	[CTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
	[MTIME_ATTR] = 6,
	[IDATA_ATTR] = 2,
	[IATTR_ATTR] = 2,
};

unsigned howbig(unsigned bits)
{
	unsigned need = 0;
	for (int kind = MIN_ATTR; kind < MAX_ATTRS; kind++)
		if ((bits & (1 << kind)))
			need += atsize[kind] + 2;
	return need;
}

unsigned howmuch(struct inode *inode)
{
	return 0;
}

int attr_check(void *attrs, unsigned size)
{
	void *limit = attrs + size;
	unsigned head;
	while (attrs < limit - 1)
	{
		attrs = decode16(attrs, &head);
		unsigned kind = head >> 12;
		if (kind < MIN_ATTR || kind >= MAX_ATTRS)
			return 0;
		if (attrs + atsize[kind] > limit)
			return 0;
		attrs += atsize[kind];
	}
	return 1;
}

void *encode_kind(void *attrs, unsigned kind, unsigned version)
{
	return encode16(attrs, (kind << 12) | version);
}

void *encode_attrs(SB, void *attrs, unsigned size, struct inode *inode)
{
	//printf("encode %u attr bytes\n", size);
	void *limit = attrs + size - 3;
	for (int kind = MIN_ATTR; kind < MAX_ATTRS; kind++) {
		if (!(inode->present & (1 << kind)))
			continue;
		if (attrs >= limit)
			break;
		attrs = encode_kind(attrs, kind, sb->version);
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

struct xattr { u16 atom, len; char data[]; } PACKED;
struct xcache { u16 size, maxsize; struct xattr xattrs[]; } PACKED;

struct xattr *xcache_next(struct xattr *xattr)
{
	return (void *)xattr->data + xattr->len;
}

struct xattr *xcache_limit(struct xcache *xcache)
{
	return (void *)xcache + xcache->size;
}

void *decode_attrs(SB, void *attrs, unsigned size, struct inode *inode)
{
	//printf("decode %u attr bytes\n", size);
	u64 v64;
	struct xattr *xattr = inode->xcache ? inode->xcache->xattrs : NULL;
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
		case IATTR_ATTR:;
			// immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
			unsigned size, atom;
			attrs = decode16(attrs, &size);
			attrs = decode16(attrs, &atom);
			*xattr = (struct xattr){ .atom = atom, .len = size - 2 };
			unsigned xsize = sizeof(*xattr) + xattr->len;
			assert((void *)xattr + xsize < (void *)inode->xcache + inode->xcache->maxsize);
			memcpy(xattr->data, attrs, xattr->len);
			attrs += xattr->len;
			inode->xcache->size += xsize;
			xattr = xcache_next(xattr);
			break;
		default:
			return NULL;
		}
		inode->present |= 1 << kind;
	}
	return attrs;
}

void dump_attrs(struct inode *inode)
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

int xcache_dump(struct inode *inode)
{
	if (!inode->xcache)
		return 0;
	//warn("xattrs %p/%i", inode->xcache, inode->xcache->size);
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *limit = xcache_limit(inode->xcache);
	while (xattr < limit) {
		if (!xattr->len)
			goto zero;
		if (xattr->len > inode->sb->blocksize)
			goto barf;
		printf("xattr %x: ", xattr->atom);
		hexdump(xattr->data, xattr->len);
		struct xattr *xnext = xcache_next(xattr);
		if (xnext > limit)
			goto over;
		xattr = xnext;
	}
	assert(xattr == limit);
	return 0;
zero:
	error("zero length xattr");
over:
	error("corrupt xattrs");
barf:
	error("xattr too big");
	return -1;
}

struct xattr *xcache_lookup(struct inode *inode, unsigned atom, int *err)
{
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *limit = xcache_limit(inode->xcache);
	while (xattr < limit) {
		if (!xattr->len)
			goto zero;
		if (xattr->atom == atom)
			return xattr;
		struct xattr *xnext = xcache_next(xattr);
		if (xnext > limit)
			goto over;
		xattr = xnext;
	}
	assert(xattr == limit);
null:
	return NULL;
zero:
	*err = EINVAL;
	error("zero length xattr");
	goto null;
over:
	*err = EINVAL;
	error("corrupt xattrs");
	goto null;
}

/*
 * Things to improve about xcache_update:
 *
 *  * It always allocates the new attribute at the end of the list because it
 *    is lazy and works by always deleting the attribute first then putting
 *    the new one at the end
 *
 *  * If the size of the attribute did not change, does unecessary work
 *
 *  * Should expand by binary factor
 */
int xcache_update(struct inode *inode, unsigned atom, void *data, unsigned len, int *err)
{
	struct xattr *xattr = inode->xcache ? xcache_lookup(inode, atom, err) : NULL;
	if (xattr) {
		unsigned size = (void *)xcache_next(xattr) - (void *)xattr;
		//warn("size = %i\n", size);
		memmove(xattr, xcache_next(xattr), inode->xcache->size -= size);
	}
	if (len) {
		unsigned more = sizeof(*xattr) + len;
		struct xcache *xcache = inode->xcache;
		if (!xcache || xcache->size + more > xcache->maxsize) {
			unsigned oldsize = xcache ? xcache->size : offsetof(struct xcache, xattrs);
			unsigned maxsize = xcache ? xcache->maxsize : (1 << 7);
			unsigned newsize = oldsize + (more < maxsize ? maxsize : more);
			struct xcache *newcache = malloc(newsize);
			if (!newcache)
				return -ENOMEM;
			*newcache = (struct xcache){ .size = oldsize, .maxsize = newsize };
			//warn("realloc to %i\n", newsize);
			if (xcache) {
				memcpy(newcache, xcache, oldsize);
				free(xcache);
			}
			inode->xcache = newcache;
		}
		xattr = xcache_limit(inode->xcache);
		//warn("expand by %i\n", more);
		inode->xcache->size += more;
		memcpy(xattr->data, data, (xattr->len = len));
		xattr->atom = atom;
	}
	return 0;
}

void *encode_xattrs(struct inode *inode, void *attrs, unsigned size)
{
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *xtop = xcache_limit(inode->xcache);
	void *limit = attrs + size - 3;
	while (xattr < xtop) {
		if (attrs >= limit)
			break;
		//immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
		//printf("xattr %x/%x ", xattr->atom, xattr->len);
		attrs = encode_kind(attrs, IATTR_ATTR, inode->sb->version);
		attrs = encode16(attrs, xattr->len + 2);
		attrs = encode16(attrs, xattr->atom);
		memcpy(attrs, xattr->data, xattr->len);
		attrs += xattr->len;
		xattr = xcache_next(xattr);
	}
	return attrs;
}

#ifndef main
#ifndef iattr_included_from_ileaf
int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	SB = &(struct sb){ .version = 0, .blocksize = 1 << 9, };
	struct inode *inode = &(struct inode){ .sb = sb,
		.present = abits, .i_mode = 0x666, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00d, .depth = 3 } },
		.i_size = 0x123456789, .i_ctime = 0xdec0debead, .i_mtime = 0xbadfaced00d };

	int err = 0;
	xcache_update(inode, 0x666, "hello", 5, &err);
	xcache_update(inode, 0x777, "world!", 6, &err);
	xcache_dump(inode);
	struct xattr *xattr = xcache_lookup(inode, 0x777, &err);
	if (xattr)
		printf("%x => %.*s\n", xattr->atom, xattr->len, xattr->data);
	xcache_update(inode, 0x111, "class", 5, &err);
	xcache_update(inode, 0x666, NULL, 0, &err);
	xcache_dump(inode);
	warn("xsize = %x\n", inode->xcache->size);
	char attrs[1000] = { };
	char *top = encode_xattrs(inode, attrs, sizeof(attrs));
	hexdump(attrs, top - attrs);
	inode->xcache->size = offsetof(struct xcache, xattrs);
	char *newtop = decode_attrs(sb, attrs, top - attrs, inode);
	assert(top == newtop);
	warn("xsize = %x\n", inode->xcache->size);
	xcache_dump(inode);
return 0;

	printf("%i attributes starting from %i\n", MAX_ATTRS - MIN_ATTR, MIN_ATTR);
	printf("need %i attr bytes\n", howbig(abits));
//	printf("decode %ti attr bytes\n", attrs - attrbase);
//	decode_attrs(sb, attrbase, attrs - attrbase, inode);
	dump_attrs(inode);
	return 0;
}
#endif
#endif
