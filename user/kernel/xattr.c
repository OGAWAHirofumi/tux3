/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

/* Xattr Atoms */

/*
 * Atom count table:
 *
 * * Both tables are mapped into the atom table at a high logical offset.
 *   Allowing 32 bits worth of atom numbers, and with at most 256 atom entries
 *   per 4K dirent block, we need about (32 << 8) = 1 TB dirent bytes for the
 *   atom dictionary, so the refcount tables start at block 2^40 >> 12 = 2^28.
 *
 * * The refcount table consists of pairs of blocks: even blocks with the low
 *   16 bits of refcount and odd blocks with the high 16 bits.  For 2^32 atoms
 *   that is 2^34 bytes at most, or 2^22 4K blocks.
 *
 * Atom reverse map:
 *
 * * When a new atom dirent is created we also set the reverse map for the
 *   dirent's atom number to the file offset at which the dirent was created.
 *   This will be 64 bits just to be lazy so that is 2^32 atoms * 8 bytes
 *   = 2^35 revmap bytes = 2^23 4K blocks. This starts just above the count
 *   table, which puts it at logical offset 2^28 + 2^23, leaving a gap after
 *   the count table in case we decide 32 bits of ref count is not enough.
 */

typedef u32 atom_t;

static inline atom_t entry_atom(tux_dirent *entry)
{
	return from_be_u32(entry->inum);
}

struct buffer_head *blockread_unatom(struct inode *atable, atom_t atom, unsigned *offset)
{
	unsigned shift = tux_sb(atable->i_sb)->blockbits - 3;
	*offset = atom & ~(-1 << shift);
	return blockread(mapping(atable), tux_sb(atable->i_sb)->unatom_base + (atom >> shift));
}

static int unatom(struct inode *atable, atom_t atom, char *name, unsigned size)
{
	unsigned offset;
	SB = tux_sb(atable->i_sb);
	struct buffer_head *buffer = blockread_unatom(atable, atom, &offset);
	if (!buffer)
		return -ENOMEM;
	u64 where = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
	brelse(buffer);
	buffer = blockread(mapping(atable), where >> sb->blockbits);
	if (!buffer)
		return -ENOMEM;
	tux_dirent *entry = bufdata(buffer) + (where & sb->blockmask);
	if (entry_atom(entry) != atom) {
		warn("atom %x reverse entry broken", atom);
		return -EINVAL;
	}
	unsigned len = entry->name_len;
	if (size) {
		if (len > size) {
			brelse(buffer);
			return -ERANGE;
		}
		memcpy(name, entry->name, len);
	}
	brelse(buffer);
	return len;
}

void dump_atoms(struct inode *atable)
{
	SB = tux_sb(atable->i_sb);
	unsigned blocks = (sb->atomgen + (sb->blockmask >> 1)) >> (sb->blockbits - 1);
	for (unsigned j = 0; j < blocks; j++) {
		unsigned block = sb->atomref_base + 2 * j;
		struct buffer_head *lobuf, *hibuf;
		if (!(lobuf = blockread(mapping(atable), block)))
			goto eek;
		if (!(hibuf = blockread(mapping(atable), block)))
			goto eek;
		be_u16 *lorefs = bufdata(lobuf), *hirefs = bufdata(hibuf);
		for (unsigned i = 0; i < (sb->blocksize >> 1); i++) {
			unsigned refs = (from_be_u16(hirefs[i]) << 16) + from_be_u16(lorefs[i]);
			if (!refs)
				continue;
			atom_t atom = i;
			char name[100];
			int len = unatom(atable, atom, name, sizeof(name));
			if (len < 0)
				goto eek;
			printf("%.*s = %x\n", len, name, atom);
		}
		brelse(lobuf);
		brelse(hibuf);
	}
	return;
eek:
	warn("atom name lookup failed");
	return;
}

void show_freeatoms(SB)
{
	struct inode *atable = sb->atable;
	atom_t atom = sb->freeatom;
	while (atom) {
		warn("free atom: %Lx", (L)atom);
		unsigned offset;
		struct buffer_head *buffer = blockread_unatom(atable, atom, &offset);
		if (!buffer)
			goto eek;
		u64 next = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
		if ((next >> 48) != 0xdead)
			goto eek;
		atom = next & ~(-1LL << 48);
		brelse(buffer);
	}
	return;
eek:
	warn("eek");
}

atom_t get_freeatom(struct inode *atable)
{
	SB = tux_sb(atable->i_sb);
	atom_t atom = sb->freeatom;
	if (!atom)
		return sb->atomgen++;
	unsigned offset;
	struct buffer_head *buffer = blockread_unatom(atable, atom, &offset);
	if (!buffer)
		goto eek;
	u64 next = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
	brelse(buffer);
	if ((next >> 48) != 0xdead)
		goto eek;
	sb->freeatom = next & ~(-1LL << 48);
	return atom;
eek:
	warn("something horrible happened");
	return -1;
}

int use_atom(struct inode *atable, atom_t atom, int use)
{
	SB = tux_sb(atable->i_sb);
	unsigned shift = sb->blockbits - 1;
	unsigned block = sb->atomref_base + 2 * (atom >> shift);
	unsigned offset = atom & ~(-1 << shift), kill = 0;
	struct buffer_head *buffer;
	if (!(buffer = blockread(mapping(atable), block)))
		return -EIO;
	int low = from_be_u16(((be_u16 *)bufdata(buffer))[offset]) + use;
	trace("inc atom %x by %i, offset %x[%x], low = %i", atom, use, block, offset, low);
	((be_u16 *)bufdata(buffer))[offset] = to_be_u16(low);
	if (!low || (low & (-1 << 16))) {
		brelse_dirty(buffer);
		if (!(buffer = blockread(mapping(atable), block + 1)))
			return -EIO;
		int high = from_be_u16(((be_u16 *)bufdata(buffer))[offset]) + (low >> 16);
		trace("carry %i, offset %x[%x], high = %i", low >> 16, block, offset, high);
		((be_u16 *)bufdata(buffer))[offset] = to_be_u16(high);
		kill = !(low | high);
	}
	brelse_dirty(buffer);
	if (kill) {
		warn("delete atom %Lx", (L) atom);
		buffer = blockread_unatom(atable, atom, &offset);
		if (!buffer)
			return -1; // better set a flag that unatom broke or something!!!
		u64 where = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
		brelse(buffer);
		((be_u64 *)bufdata(buffer))[offset] = to_be_u64((u64)sb->freeatom | (0xdeadLL << 48));
		sb->freeatom = atom;
		buffer = blockread(mapping(atable), where >> sb->blockbits);
		tux_dirent *entry = bufdata(buffer) + (where & sb->blockmask);
		if (entry_atom(entry) == atom)
			tux_delete_entry(buffer, entry);
		else {
			warn("atom entry not found");
			brelse(buffer);
		}
	}
	return 0;
}

atom_t find_atom(struct inode *atable, char *name, unsigned len)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_entry(atable, name, len, &buffer);
	if (!entry)
		return -1;
	atom_t atom = entry_atom(entry);
	brelse(buffer);
	return atom;
}

atom_t make_atom(struct inode *atable, char *name, unsigned len)
{
	atom_t atom = find_atom(atable, name, len);
	if (atom != -1)
		return atom;
	atom = get_freeatom(atable);
	loff_t where = tux_create_entry(atable, name, len, atom, 0);
	if (where < 0)
		return -1; // and what about the err???

	/* Enter into reverse map - maybe verify zero refs? */
	unsigned offset;
	struct buffer_head *buffer = blockread_unatom(atable, atom, &offset);
	if (!buffer)
		return -1; // better set a flag that unatom broke or something!!!
	((be_u64 *)bufdata(buffer))[offset] = to_be_u64(where);
	brelse_dirty(buffer);

	return atom;
}

/* Xattr cache */

int xcache_dump(struct inode *inode)
{
	if (!tux_inode(inode)->xcache)
		return 0;
	//warn("xattrs %p/%i", inode->xcache, inode->xcache->size);
	struct xcache *xcache = tux_inode(inode)->xcache;
	struct xattr *xattr = xcache->xattrs, *limit = xcache_limit(xcache);
	while (xattr < limit) {
		if (xattr->size > tux_sb(inode->i_sb)->blocksize)
			goto bail;
		printf("atom %.3x => ", xattr->atom);
		xattr->size ? hexdump(xattr->body, xattr->size) : printf("<empty>\n");
		if ((xattr = xcache_next(xattr)) > limit)
			goto fail;
	}
	assert(xattr == limit);
	return 0;
fail:
	error("corrupt xattrs");
bail:
	error("xattr too big");
	return -1;
}

struct xattr *xcache_lookup(struct xcache *xcache, unsigned atom, int *err)
{
	if (!xcache)
		return NULL;
	struct xattr *xattr = xcache->xattrs;
	struct xattr *limit = xcache_limit(xcache);
	while (xattr < limit) {
		if (xattr->atom == atom)
			return xattr;
		if ((xattr = xcache_next(xattr)) > limit)
			goto fail;
	}
	assert(xattr == limit);
null:
	return NULL;
fail:
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

static inline int remove_old(struct xcache *xcache, struct xattr *xattr)
{
	if (!xattr)
		return 0;
	unsigned size = (void *)xcache_next(xattr) - (void *)xattr;
	memmove(xattr, xcache_next(xattr), xcache->size -= size);
	return 1;
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
int xcache_update(struct inode *inode, unsigned atom, void *data, unsigned len, unsigned flags)
{
	int err = 0, use = 0;
	struct xcache *xcache = tux_inode(inode)->xcache;
	struct xattr *xattr = xcache_lookup(xcache, atom, &err);
	if (xattr) {
		if (flags & XATTR_CREATE)
			return -EEXIST;
		use -= remove_old(xcache, xattr);
	} else if (flags & XATTR_REPLACE)
		return -ENOATTR;

	/* Insert new */
	unsigned more = sizeof(*xattr) + len;
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
		tux_inode(inode)->xcache = newcache;
	}
	xattr = xcache_limit(tux_inode(inode)->xcache);
	//warn("expand by %i\n", more);
	tux_inode(inode)->xcache->size += more;
	memcpy(xattr->body, data, (xattr->size = len));
	xattr->atom = atom;
	use++;
	if (use)
		use_atom(tux_sb(inode->i_sb)->atable, atom, use);
	return 0;
}

struct xattr *get_xattr(struct inode *inode, char *name, unsigned len)
{
	int err = 0;
	atom_t atom = find_atom(tux_sb(inode->i_sb)->atable, name, len);
	if (atom == -1)
		return NULL;
	return xcache_lookup(tux_inode(inode)->xcache, atom, &err); // and what about the err???
}

int set_xattr(struct inode *inode, char *name, unsigned len, void *data, unsigned size, unsigned flags)
{
	atom_t atom = make_atom(tux_sb(inode->i_sb)->atable, name, len);
	if (atom == -1)
		return -EINVAL;
	return xcache_update(inode, atom, data, size, flags);
}

int del_xattr(struct inode *inode, char *name, unsigned len)
{
	int err = 0;
	atom_t atom = find_atom(tux_sb(inode->i_sb)->atable, name, len);
	if (atom == -1)
		return -ENOATTR;
	struct xcache *xcache = tux_inode(inode)->xcache;
	struct xattr *xattr = xcache_lookup(xcache, atom, &err);
	if (err)
		return err;
	if (!xattr)
		return -ENOATTR;
	int used = remove_old(xcache, xattr);
	if (used)
		use_atom(tux_sb(inode->i_sb)->atable, atom, -used);
	return err;
}

int xattr_list(struct inode *inode, char *text, size_t size, char *prefix, unsigned bogus)
{
	if (!tux_inode(inode)->xcache)
		return 0;
	struct inode *atable = tux_sb(inode->i_sb)->atable;
	struct xcache *xcache = tux_inode(inode)->xcache;
	struct xattr *xattr = xcache->xattrs, *limit = xcache_limit(xcache);
	char *base = text, *top = text + size;
	while (xattr < limit) {
		atom_t atom = xattr->atom;
		if (size) {
			int tail = top - text - bogus;
			if (tail < 0)
				goto full;
			int len = unatom(atable, atom, text + bogus, tail);
			if (len < 0 || len == tail)
				goto full;
			memcpy(text, prefix, bogus);
			*(text += bogus + len) = 0;
			text++;
		} else
			text += bogus + unatom(atable, atom, NULL, 0) + 1;
		if ((xattr = xcache_next(xattr)) > limit)
			goto fail;
	}
	assert(xattr == limit);
full:
	return text - base;
fail:
	return -EINVAL;
}

/* Xattr encode/decode */

void *encode_xattrs(struct inode *inode, void *attrs, unsigned size)
{
	if (!tux_inode(inode)->xcache)
		return attrs;
	struct xattr *xattr = tux_inode(inode)->xcache->xattrs;
	struct xattr *xtop = xcache_limit(tux_inode(inode)->xcache);
	void *limit = attrs + size - 3;
	while (xattr < xtop) {
		if (attrs >= limit)
			break;
		//immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
		//printf("xattr %x/%x ", xattr->atom, xattr->size);
		attrs = encode_kind(attrs, XATTR_ATTR, tux_sb(inode->i_sb)->version);
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
	SB = tux_sb(inode->i_sb);
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
	if (!tux_inode(inode)->xcache)
		return 0;
	unsigned size = 0, xatsize = atsize[XATTR_ATTR];
	struct xattr *xattr = tux_inode(inode)->xcache->xattrs;
	struct xattr *limit = xcache_limit(tux_inode(inode)->xcache);
	while (xattr < limit) {
		size += 2 + xatsize + xattr->size;
		xattr = xcache_next(xattr);
	}
	assert(xattr == limit);
	return size;
}
