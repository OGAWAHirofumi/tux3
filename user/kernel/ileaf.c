/*
 * Inode table btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 2
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

struct ileaf {
	be_u16 magic;		/* Magic number */
	be_u16 count;		/* Counts of used offset info entries */
	u32 pad;
	be_u64 ibase;		/* Base inode number */
	char table[];		/* ileaf data: inode attrs ... offset info */
};

/*
 * inode leaf format
 *
 * A leaf has a small header followed by a table of attributes.  A vector of
 * offsets within the block grows down from the top of the leaf towards the
 * top of the attribute table, indexed by the difference between inum and
 * leaf->ibase, the base inum of the table block.
 */

static inline unsigned __atdict(be_u16 *dict, unsigned at)
{
	assert(at);
	return from_be_u16(*(dict - at));
}

static inline unsigned atdict(be_u16 *dict, unsigned at)
{
	return at ? __atdict(dict, at) : 0;
}

static inline void add_idict(be_u16 *dict, int n)
{
	*dict = to_be_u16(from_be_u16(*dict) + n);
}

static inline unsigned icount(struct ileaf *leaf)
{
	return from_be_u16(leaf->count);
}

static inline tuxkey_t ibase(struct ileaf *leaf)
{
	return from_be_u64(leaf->ibase);
}

static void ileaf_btree_init(struct btree *btree)
{
	btree->entries_per_leaf = 1 << (btree->sb->blockbits - 6);
}

static int ileaf_init(struct btree *btree, vleaf *leaf)
{
	trace("initialize inode leaf %p", leaf);
	*(struct ileaf *)leaf = (struct ileaf){ to_be_u16(TUX3_MAGIC_ILEAF) };
	return 0;
}

static int ileaf_sniff(struct btree *btree, vleaf *leaf)
{
	return ((struct ileaf *)leaf)->magic == to_be_u16(TUX3_MAGIC_ILEAF);
}

static unsigned ileaf_need(struct btree *btree, vleaf *vleaf)
{
	be_u16 *dict = vleaf + btree->sb->blocksize;
	unsigned count = icount(to_ileaf(vleaf));

	return atdict(dict, count) + count * sizeof(*dict);
}

static unsigned ileaf_free(struct btree *btree, vleaf *leaf)
{
	return btree->sb->blocksize - ileaf_need(btree, leaf) - sizeof(struct ileaf);
}

static void ileaf_dump(struct btree *btree, vleaf *vleaf)
{
	if (!tux3_trace)
		return;
	struct sb *sb = btree->sb;
	struct ileaf *leaf = vleaf;
	inum_t inum = ibase(leaf);
	be_u16 *dict = vleaf + sb->blocksize;
	unsigned offset = 0;

	printf("inode table block 0x%Lx/%i (%x bytes free)\n", (L)ibase(leaf), icount(leaf), ileaf_free(btree, leaf));
	for (int i = 0; i < icount(leaf); i++, inum++) {
		int limit = __atdict(dict, i + 1), size = limit - offset;
		if (!size)
			continue;
		printf("  0x%Lx: ", (L)inum);
		//printf("[%x] ", offset);
		if (size < 0)
			printf("<corrupt>\n");
		else if (!size)
			printf("<empty>\n");
		else {
			/* FIXME: this doesn't work in kernel */
			struct inode inode = { .i_sb = vfs_sb(btree->sb) };
			unsigned xsize = decode_xsize(&inode, leaf->table + offset, size);
			tux_inode(&inode)->xcache = xsize ? new_xcache(xsize) : NULL;
			decode_attrs(&inode, leaf->table + offset, size);
			dump_attrs(&inode);
			xcache_dump(&inode);
			free(tux_inode(&inode)->xcache);
		}
		offset = limit;
	}
}

void *ileaf_lookup(struct btree *btree, inum_t inum, struct ileaf *leaf, unsigned *result)
{
	assert(inum >= ibase(leaf));
	assert(inum < ibase(leaf) + btree->entries_per_leaf);
	unsigned at = inum - ibase(leaf), size = 0;
	void *attrs = NULL;

	trace("lookup inode 0x%Lx, %Lx + %x", (L)inum, (L)ibase(leaf), at);
	if (at < icount(leaf)) {
		be_u16 *dict = (void *)leaf + btree->sb->blocksize;
		unsigned offset = atdict(dict, at);
		if ((size = __atdict(dict, at + 1) - offset))
			attrs = leaf->table + offset;
	}
	*result = size;
	return attrs;
}

static int isinorder(struct btree *btree, struct ileaf *leaf)
{
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;

	for (int i = 0, offset = 0, limit; i < icount(leaf); i++, offset = limit)
		if ((limit = __atdict(dict, i + 1)) < offset)
			return 0;
	return 1;
}

/* userland only */
int ileaf_check(struct btree *btree, struct ileaf *leaf)
{
	char *why;

	why = "not an inode table leaf";
	if (leaf->magic != to_be_u16(TUX3_MAGIC_ILEAF))
		goto eek;
	why = "dict out of order";
	if (!isinorder(btree, leaf))
		goto eek;
	return 0;
eek:
	printf("%s!\n", why);
	return -1;
}

static void ileaf_trim(struct btree *btree, struct ileaf *leaf)
{
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	unsigned count = icount(leaf);

	while (count > 1 && *(dict - count) == *(dict - count + 1))
		count--;
	if (count == 1 && !*(dict - 1))
		count = 0;
	leaf->count = to_be_u16(count);
}

#define SPLIT_AT_INUM

static tuxkey_t ileaf_split(struct btree *btree, tuxkey_t hint,
			    vleaf *from, vleaf *into)
{
	assert(ileaf_sniff(btree, from));
	struct ileaf *leaf = from, *dest = into;
	be_u16 *dict = from + btree->sb->blocksize, *destdict = into + btree->sb->blocksize;

#ifdef SPLIT_AT_INUM
	trace("split at inum 0x%Lx", (L)hint);
	assert(hint >= ibase(leaf));
	unsigned at = min_t(tuxkey_t, hint - ibase(leaf), icount(leaf));
#else
	/* binsearch inum starting nearest middle of block */
	unsigned at = 1, hi = icount(leaf);
	while (at < hi) {
		int mid = (at + hi) / 2;
		if (*(dict - mid) < (btree->sb->blocksize / 2))
			at = mid + 1;
		else
			hi = mid;
	}
#endif
	/* should trim leading empty inodes on copy */
	unsigned split = atdict(dict, at), free = atdict(dict, icount(leaf));
	trace("split at %x of %x", at, icount(leaf));
	trace("copy out %x bytes at %x", free - split, split);
	assert(free >= split);
	memcpy(dest->table, leaf->table + split, free - split);
	dest->count = to_be_u16(icount(leaf) - at);
	veccopy(destdict - icount(dest), dict - icount(leaf), icount(dest));
	for (int i = 1; i <= icount(dest); i++)
		add_idict(destdict - i, -split);
#ifdef SPLIT_AT_INUM
	/* round down to multiple of 64 above ibase */
	inum_t round = hint & ~(inum_t)(btree->entries_per_leaf - 1);
	dest->ibase = to_be_u64(round > ibase(leaf) + icount(leaf) ? round : hint);
#else
	dest->ibase = to_be_u64(ibase(leaf) + at);
#endif
	leaf->count = to_be_u16(at);
	memset(leaf->table + split, 0, (char *)(dict - icount(leaf)) - (leaf->table + split));
	ileaf_trim(btree, leaf);
	return ibase(dest);
}

/* userland only */
void ileaf_merge(struct btree *btree, struct ileaf *leaf, struct ileaf *from)
{
	if (!icount(from))
		return;
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	be_u16 *fromdict = (void *)from + btree->sb->blocksize;
	unsigned at = icount(leaf), free = atdict(dict, at), size = atdict(fromdict, icount(from));

	trace("copy in %i bytes", size);
	memcpy(leaf->table + free, from->table, size);
	leaf->count = to_be_u16(at + icount(from));
	veccopy(dict - icount(leaf), fromdict - icount(from), icount(from));
	for (int i = at + 1; at && i <= at + icount(from); i++)
		add_idict(dict - i, __atdict(dict, at));
}

static void *ileaf_resize(struct btree *btree, tuxkey_t inum, vleaf *base, unsigned newsize)
{
	struct ileaf *leaf = base;
	assert(ileaf_sniff(btree, leaf));
	assert(inum >= ibase(leaf));
	if (inum - ibase(leaf) >= btree->entries_per_leaf)
		return NULL;

	be_u16 *dict = base + btree->sb->blocksize;
	unsigned at = inum - ibase(leaf);
	unsigned count = icount(leaf);
	unsigned extend_empty = at < count ? 0 : at - count + 1;
	unsigned offset = at && count ? __atdict(dict, min(at, count)) : 0;
	unsigned size = at < count ? __atdict(dict, at + 1) - offset : 0;
	int more = newsize - size;

	if (more > 0 && sizeof(*dict) * extend_empty + more > ileaf_free(btree, leaf))
		return NULL;
	be_u16 limit = to_be_u16(atdict(dict, count));
	for (; extend_empty--; count++)
		*(dict - count - 1) = limit;
	unsigned itop = __atdict(dict, count);
	void *attrs = leaf->table + offset;
	trace("resize inum 0x%Lx at 0x%x from %x to %x", (L)inum, offset, size, newsize);

	assert(itop >= offset + size);
	memmove(attrs + newsize, attrs + size, itop - offset - size);
	for (int i = at + 1; i <= count; i++)
		add_idict(dict - i, more);
	leaf->count = to_be_u16(count);
	return attrs;
}

inum_t find_empty_inode(struct btree *btree, struct ileaf *leaf, inum_t goal)
{
	assert(goal >= ibase(leaf));
	if (goal - ibase(leaf) >= btree->entries_per_leaf)
		return goal;
	unsigned at = goal - ibase(leaf);

	if (at < icount(leaf)) {
		be_u16 *dict = (void *)leaf + btree->sb->blocksize;
		unsigned offset = atdict(dict, at);
		for (; at < icount(leaf); at++) {
			unsigned limit = __atdict(dict, at + 1);
			if (offset == limit)
				break;
			offset = limit;
		}
	}
	return ibase(leaf) + at;
}

int ileaf_enum_inum(struct btree *btree, struct ileaf *ileaf,
		    int (*func)(struct btree *, inum_t, void *, u16, void *),
		    void *func_data)
{
	be_u16 *dict = (void *)ileaf + btree->sb->blocksize;
	int at, offset;

	offset = 0;
	for (at = 0; at < icount(ileaf); at++) {
		inum_t inum;
		int err, limit, size;

		limit = __atdict(dict, at + 1);
		if (limit <= offset)
			continue;
		size = limit - offset;

		inum = ibase(ileaf) + at;
		err = func(btree, inum, ileaf->table + offset, size, func_data);
		if (err)
			return err;

		offset = limit;
	}

	return 0;
}

void ileaf_purge(struct btree *btree, inum_t inum, struct ileaf *leaf)
{
	assert(inum >= ibase(leaf));
	assert(inum - ibase(leaf) < btree->entries_per_leaf);
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	unsigned at = inum - ibase(leaf);
	unsigned offset = atdict(dict, at);
	unsigned size = __atdict(dict, at + 1) - offset;

	trace("delete inode %Lx from %p[%x/%x]", (L)inum, leaf, at, size);
	assert(size);
	unsigned free = __atdict(dict, icount(leaf)), tail = free - offset - size;
	assert(offset + size + tail <= free);
	memmove(leaf->table + offset, leaf->table + offset + size, tail);
	for (int i = at + 1; i <= icount(leaf); i++)
		add_idict(dict - i, -size);
	ileaf_trim(btree, leaf);
}

struct btree_ops itable_ops = {
	.btree_init = ileaf_btree_init,
	.leaf_dump = ileaf_dump,
	.leaf_sniff = ileaf_sniff,
	.leaf_init = ileaf_init,
	.leaf_split = ileaf_split,
	.leaf_resize = ileaf_resize,
	.balloc = balloc,
};
