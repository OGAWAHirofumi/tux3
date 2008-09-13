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
		printf("atom %x => ", xattr->atom);
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

struct xcache *new_xcache(unsigned maxsize)
{
	warn("realloc xcache to %i", maxsize);
	struct xcache *xcache = malloc(maxsize);
	if (!xcache)
		return NULL;
	*xcache = (struct xcache){ .size = offsetof(struct xcache, xattrs), .maxsize = maxsize };
	return xcache;
}

#ifndef main
#define main notmain2
#include "ileaf.c"
#undef main
#endif

typedef fieldtype(ext2_dirent, inum) atom_t; // just for now

/*
 * Atom refcount table and refcount high
 *
 * * Both tables are mapped into the atom table at a high logical offset.
 *   Allowing 32 bits worth of atom numbers, and with at most 256 atom
 *   entries per 4K dirent block, we need at most (32 << 8) = 1 TB dirent
 *   bytes for the atom dictionary, so the count tables start at block
 *   number 2^40 >> 12 = 2^28.
 *
 * * The low end count table needs 2^33 bytes at most, or 2^21 blocks, so
 *   the high count table starts just above it at 2^28 + 2^21 blocks.
 *
 * Atom reverse map
 *
 * * When a new atom dirent is created we also set the reverse map for the
 *   dirent's atom number to the file offset at which the dirent was created.
 *   This will be 64 bits just to be lazy so that is 2^32 atoms * 8 bytes
 *   = 2^35 revmap bytes = 2^35 >> 12 blocks = 2^23 blocks.  We locate this
 *   just above the count table (low + high part) which puts it at logical
 *   offset 2^28 + 2^23, since the refcount table is also (by coincidence)
 *   2^23 bytes in size.
 */

int use_atom(struct inode *inode, atom_t atom, int use)
{
#ifdef main
	return 0; // not ready for prime time
#endif
	unsigned shift = inode->sb->blockbits - 1;
	unsigned block = inode->sb->atomref_base + 2 * (atom >> shift);
	unsigned offset = atom & ~(-1 << shift);
	struct buffer *buffer;
	if (!(buffer = bread(inode->map, block)))
		return -EIO;
	int low = from_be_u16(((be_u16 *)buffer->data)[offset]) + use;
	trace("inc atom %x by %i, offset %x[%x], low = %i", atom, use, block, offset, low);
	((be_u16 *)buffer->data)[offset] = to_be_u16(low);
	if ((low & (-1 << 16))) {
		brelse_dirty(buffer);
		if (!(buffer = bread(inode->map, block + 1)))
			return -EIO;
		int high = from_be_u16(((be_u16 *)buffer->data)[offset]) + (low >> 16);
		trace("carry %i, offset %x[%x], high = %i", low >> 16, block, offset, high);
		((be_u16 *)buffer->data)[offset] = to_be_u16(high);
	}
	brelse_dirty(buffer);
	return 0;
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
	int err = 0, use = 0;
	struct xattr *xattr = inode->xcache ? xcache_lookup(inode, atom, &err) : NULL;
	if (xattr) {
		unsigned size = (void *)xcache_next(xattr) - (void *)xattr;
		//warn("size = %i\n", size);
		memmove(xattr, xcache_next(xattr), inode->xcache->size -= size);
		use--;
	}
	if (len) {
		unsigned more = sizeof(*xattr) + len;
		struct xcache *xcache = inode->xcache;
		if (!xcache || xcache->size + more > xcache->maxsize) {
			unsigned oldsize = xcache ? xcache->size : offsetof(struct xcache, xattrs);
			unsigned maxsize = xcache ? xcache->maxsize : (1 << 7);
			unsigned newsize = oldsize + (more < maxsize ? maxsize : more);
			struct xcache *newcache = new_xcache(newsize);
			if (!newcache)
				return -ENOMEM;
			if (xcache) {
				memcpy(newcache->xattrs, xcache->xattrs, oldsize - offsetof(struct xcache, xattrs));
				newcache->size = oldsize;
				free(xcache);
			}
			inode->xcache = newcache;
		}
		xattr = xcache_limit(inode->xcache);
		//warn("expand by %i\n", more);
		inode->xcache->size += more;
		memcpy(xattr->body, data, (xattr->size = len));
		xattr->atom = atom;
		use++;
	}
	if (use)
		use_atom(inode, atom, use);
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
		attrs = encode_kind(attrs, XATTR_ATTR, inode->sb->version);
		attrs = encode16(attrs, xattr->size + 2);
		attrs = encode16(attrs, xattr->atom);
		memcpy(attrs, xattr->body, xattr->size);
		attrs += xattr->size;
		xattr = xcache_next(xattr);
	}
	return attrs;
}

unsigned decode_xsize(struct inode *inode, void *attrs, unsigned size)
{
	SB = inode->sb;
	unsigned total = 0, bytes;
	void *limit = attrs + size;
	while (attrs < limit - 1) {
		unsigned head, kind;
		attrs = decode16(attrs, &head);
		switch ((kind = head >> 12)) {
		case XATTR_ATTR:
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

unsigned encode_xsize(struct inode *inode)
{
	if (!inode->xcache)
		return 0;
	unsigned size = 0, xatsize = atsize[XATTR_ATTR];
	struct xattr *xattr = inode->xcache->xattrs;
	struct xattr *limit = xcache_limit(inode->xcache);
	while (xattr < limit) {
		size += 2 + xatsize + xattr->size;
		xattr = xcache_next(xattr);
	}
	assert(xattr == limit);
	return size;
}

atom_t find_atom(struct inode *inode, char *name, unsigned len)
{
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(inode, name, len, &buffer);
	if (!entry)
		return -1;
	atom_t atom = entry->inum;
	brelse(buffer);
	return atom;
}

static inline unsigned unatom_shift(struct inode *inode)
{
	return inode->sb->blockbits - 3;
}

struct buffer *get_unatom_block(struct inode *inode, atom_t atom)
{
	return bread(inode->map, inode->sb->unatom_base + (atom >> unatom_shift(inode)));
}

atom_t make_atom(struct inode *inode, char *name, unsigned len)
{
	atom_t atom = find_atom(inode->sb->atable, name, len);
	if (atom != -1)
		return atom;
	atom = inode->sb->atomgen++; /* use refcount for allocation */
	loff_t where = ext2_create_entry(inode, name, len, atom, 0);
	if (where < 0)
		return -1; // and what about the err???
	use_atom(inode, atom, 1);

	struct buffer *buffer = get_unatom_block(inode, atom);
	if (!buffer)
		return -1; // better set a flag that unatom broke!!!
	((be_u64 *)buffer->data)[atom & ~(-1 << unatom_shift(inode))] = to_be_u64(where);
	brelse_dirty(buffer);

	return atom;
}

struct xattr *get_xattr(struct inode *inode, char *name, unsigned len)
{
	int err = 0;
	atom_t atom = find_atom(inode->sb->atable, name, len);
	if (atom == -1)
		return NULL;
	return xcache_lookup(inode, atom, &err); // and what about the err???
}

int set_xattr(struct inode *inode, char *name, unsigned len, void *data, unsigned size)
{
	atom_t atom = make_atom(inode->sb->atable, name, len);
	if (atom == -1)
		return -ENOENT;
	return xcache_update(inode, atom, data, size);
}

#ifndef main
#include <fcntl.h>

int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct dev *dev = &(struct dev){ .bits = 8, .fd = open(argv[1], O_CREAT|O_RDWR, S_IRWXU) };
	ftruncate(dev->fd, 1 << 24);
	struct map *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	SB = &(struct sb){
		.version = 0, .atable = map->inode,
		.blockbits = dev->bits, 
		.blocksize = 1 << dev->bits, 
		.blockmask = (1 << dev->bits) - 1, 
		.atomref_base = 1 << 10,
		.unatom_base = 1 << 11,
	};
	struct inode *inode = &(struct inode){ .sb = sb,
		.map = map, .i_mode = S_IFDIR | 0x666,
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00d, .depth = 3 } },
		.i_ctime = 0xdec0debead, .i_mtime = 0xbadfaced00d };
	map->inode = inode;
	sb->atable = inode;

	for (int i = 0; i < 2; i++) {
		struct buffer *buffer = getblk(inode->map, inode->sb->atomref_base + i);
		memset(buffer->data, 0, sb->blocksize);
		brelse_dirty(buffer);
	}

	/* test positive and negative refcount carry */
	use_atom(inode, 6, 1 << 15);
	use_atom(inode, 6, (1 << 15));
	use_atom(inode, 6, -(1 << 15));
	use_atom(inode, 6, -(1 << 15));

	/* test atom table */
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));

	/* test inode xattr cache */
	int err = 0;
	err = xcache_update(inode, 0x666, "hello", 5);
	err = xcache_update(inode, 0x777, "world!", 6);
	xcache_dump(inode);
	struct xattr *xattr = xcache_lookup(inode, 0x777, &err);
	if (xattr)
		printf("atom %x => %.*s\n", xattr->atom, xattr->size, xattr->body);
	err = xcache_update(inode, 0x111, "class", 5);
	err = xcache_update(inode, 0x666, NULL, 0);
	err = xcache_update(inode, 0x222, "boooyah", 7);
	xcache_dump(inode);

	/* test xattr inode table encode and decode */
	char attrs[1000] = { };
	char *top = encode_xattrs(inode, attrs, sizeof(attrs));
	hexdump(attrs, top - attrs);
	printf("predicted size = %x, encoded size = %x\n", encode_xsize(inode), top - attrs);
	inode->xcache->size = offsetof(struct xcache, xattrs);
	char *newtop = decode_attrs(inode, attrs, top - attrs);
	printf("predicted size = %x, xcache size = %x\n", decode_xsize(inode, attrs, top - attrs), inode->xcache->size);
	assert(top == newtop);
	xcache_dump(inode);
	free(inode->xcache);
	inode->xcache = NULL;

	/* test high level ops */
	set_xattr(inode, "hello", 5, "world!", 6);
	set_xattr(inode, "foo", 3, "foobar", 6);
	xcache_dump(inode);
	for (int i = 0; i < 3; i++) {
		char *namelist[] = { "hello", "foo", "world" }, *name = namelist[i];
		if ((xattr = get_xattr(inode, name, strlen(name))))
			printf("found xattr %.*s => %.*s\n", strlen(name), name, xattr->size, xattr->body);
		else
			printf("xattr %.*s not found\n", strlen(name), name);
	}
	show_buffers(map);

	for (int i = 0; i < 5; i++) {
		unsigned atom = i;
		struct buffer *buffer = get_unatom_block(inode, atom);
		loff_t unatom = from_be_u64(((be_u64 *)buffer->data)[atom & ~(-1 << unatom_shift(inode))]);
		brelse_dirty(buffer);
		trace("atom %Lu => unatom %Lu", (L)atom, (L)unatom);
		buffer = bread(inode->map, unatom >> sb->blockbits);
		hexdump(buffer->data + (unatom & sb->blockmask), 16);
		brelse(buffer);
	}

	if (0) {
		struct buffer *buffer = getblk(inode->map, inode->sb->atomref_base);
		hexdump(buffer->data, 32);
		brelse(buffer);
	}
}
#endif
