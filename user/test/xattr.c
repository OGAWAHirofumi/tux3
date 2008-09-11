/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef main
#ifndef trace
#define trace trace_on
#endif

#define main notmain0
#include "balloc.c"
#undef main

#define main notmain2
#include "ileaf.c"
#undef main

#define main notmain3
#include "dir.c"
#undef main
#endif

int xcache_dump(struct inode *inode)
{
	if (!inode->xcache)
		return 0;
	//warn("xattrs %p/%i", inode->xcache, inode->xcache->size);
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *limit = xcache_limit(inode->xcache);
	while (xattr < limit) {
		if (!xattr->size)
			goto zero;
		if (xattr->size > inode->sb->blocksize)
			goto barf;
		printf("{%x} => ", xattr->atom);
		hexdump(xattr->body, xattr->size);
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
		if (!xattr->size)
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
int xcache_update(struct inode *inode, unsigned atom, void *data, unsigned len)
{
	int err = 0;
	struct xattr *xattr = inode->xcache ? xcache_lookup(inode, atom, &err) : NULL;
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
		memcpy(xattr->body, data, (xattr->size = len));
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
		//printf("xattr %x/%x ", xattr->atom, xattr->size);
		attrs = encode_kind(attrs, IATTR_ATTR, inode->sb->version);
		attrs = encode16(attrs, xattr->size + 2);
		attrs = encode16(attrs, xattr->atom);
		memcpy(attrs, xattr->body, xattr->size);
		attrs += xattr->size;
		xattr = xcache_next(xattr);
	}
	return attrs;
}

unsigned count_xattrs(struct inode *inode, void *attrs, unsigned size)
{
	SB = inode->sb;
	unsigned total = 0, bytes;
	void *limit = attrs + size;
	while (attrs < limit - 1) {
		unsigned head, kind;
		attrs = decode16(attrs, &head);
		switch ((kind = head >> 12)) {
		case IATTR_ATTR:
		case IDATA_ATTR:
			// immediate data: kind+version:16, bytes:16, data[bytes]
			// immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
			attrs = decode16(attrs, &bytes);
			attrs += bytes;
			if ((head & 0xfff) == sb->version)
				total += sizeof(struct xattr) + bytes - 2;
			continue;
		}
		attrs += atsize[kind];
	}
	return total + sizeof(struct xcache);
}

unsigned howmuch(struct inode *inode)
{
	if (!inode->xcache)
		return 0;
	unsigned size = 0, xatsize = atsize[IATTR_ATTR];
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *limit = xcache_limit(inode->xcache);
	while (xattr < limit) {
		size += 2 + xatsize + xattr->size;
		xattr = xcache_next(xattr);
	}
	assert(xattr == limit);
	return size;
}

typedef fieldtype(ext2_dirent, inum) atom_t; // just for now

atom_t get_atom(struct inode *dir, char *name, unsigned len)
{
	atom_t atom;
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (entry) {
		atom = entry->inum;
		brelse(buffer);
		return atom;
	}
	atom = dir->sb->atomgen++; /* need refcounts and allocation */
	if (!ext2_create_entry(dir, name, len, atom, 0))
		return atom;
	return -1;
}

struct xattr *get_xattr(struct inode *inode, char *name, unsigned len)
{
	int err = 0;
	atom_t atom = get_atom(inode->sb->atable, name, len);
	struct xattr *xattr = xcache_lookup(inode, atom, &err);
	return xattr;
}

int set_xattr(struct inode *inode, char *name, unsigned len, void *data, unsigned size)
{
	atom_t atom = get_atom(inode->sb->atable, name, len);
	return xcache_update(inode, atom, data, size);
}

#ifndef main
int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;

	struct dev *dev = &(struct dev){ .bits = 8 };
	struct map *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	SB = &(struct sb){ .version = 0, .blocksize = 1 << 9, .atable = map->inode };
	struct inode *inode = &(struct inode){ .sb = sb,
		.map = map, .i_mode = S_IFDIR | 0x666,
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00d, .depth = 3 } },
		.i_ctime = 0xdec0debead, .i_mtime = 0xbadfaced00d };
	map->inode = inode;
	sb->atable = inode;

	/* test atom table */
	inode->sb->atomgen = 1; /* inum zero means empty dirent in ext2?! */
	printf("atom = %Lx\n", (L)get_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)get_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)get_atom(inode, "bar", 3));
	printf("atom = %Lx\n", (L)get_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)get_atom(inode, "bar", 3));

	/* test inode xattr cache */
	int err = 0;
	err = xcache_update(inode, 0x666, "hello", 5);
	err = xcache_update(inode, 0x777, "world!", 6);
	xcache_dump(inode);
	struct xattr *xattr = xcache_lookup(inode, 0x777, &err);
	if (xattr)
		printf("{%x} => %.*s\n", xattr->atom, xattr->size, xattr->body);
	err = xcache_update(inode, 0x111, "class", 5);
	err = xcache_update(inode, 0x666, NULL, 0);
	err = xcache_update(inode, 0x222, "boooyah", 7);
	xcache_dump(inode);

	/* test xattr inode table encode and decode */
	char attrs[1000] = { };
	char *top = encode_xattrs(inode, attrs, sizeof(attrs));
	hexdump(attrs, top - attrs);
	printf("predicted size = %x, encoded size = %x\n", howmuch(inode), top - attrs);
	inode->xcache->size = offsetof(struct xcache, xattrs);
	char *newtop = decode_attrs(inode, attrs, top - attrs);
	printf("predicted size = %x, xcache size = %x\n", count_xattrs(inode, attrs, top - attrs), inode->xcache->size);
	assert(top == newtop);
	xcache_dump(inode);
	free(inode->xcache);
	inode->xcache = NULL;

	/* test high level ops */
	set_xattr(inode, "foo", 3, "bar", 3);
	xcache_dump(inode);
	xattr = get_xattr(inode, "foo", 3);
	if (xattr)
		printf("found xattr %.*s\n", xattr->size, xattr->body);

	show_buffers(map);
}
#endif
