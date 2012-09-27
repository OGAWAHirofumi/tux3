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
#include "ileaf.h"

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

static inline be_u16 *ileaf_dict(struct btree *btree, struct ileaf *ileaf)
{
	return (void *)ileaf + btree->sb->blocksize;
}

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
	*(struct ileaf *)leaf = (struct ileaf){
		.magic = to_be_u16(TUX3_MAGIC_ILEAF),
	};
	return 0;
}

static int ileaf_need(struct btree *btree, struct ileaf *ileaf)
{
	be_u16 *dict = ileaf_dict(btree, ileaf);
	unsigned count = icount(ileaf);
	return atdict(dict, count) + count * sizeof(*dict);
}

static int ileaf_free(struct btree *btree, struct ileaf *ileaf)
{
	return btree->sb->blocksize
		- ileaf_need(btree, ileaf) - sizeof(struct ileaf);
}

static int ileaf_sniff(struct btree *btree, vleaf *leaf)
{
	return ((struct ileaf *)leaf)->magic == to_be_u16(TUX3_MAGIC_ILEAF);
}

static void ileaf_dump(struct btree *btree, vleaf *vleaf)
{
	if (!tux3_trace)
		return;
	struct ileaf *leaf = vleaf;
	inum_t inum = ibase(leaf);
	be_u16 *dict = ileaf_dict(btree, leaf);
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
		be_u16 *dict = ileaf_dict(btree, leaf);
		unsigned offset = atdict(dict, at);
		if ((size = __atdict(dict, at + 1) - offset))
			attrs = leaf->table + offset;
	}
	*result = size;
	return attrs;
}

static int isinorder(struct btree *btree, struct ileaf *leaf)
{
	be_u16 *dict = ileaf_dict(btree, leaf);

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
	be_u16 *dict = ileaf_dict(btree, leaf);
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
	be_u16 *dict = ileaf_dict(btree, from);
	be_u16 *destdict = ileaf_dict(btree, into);

#ifdef SPLIT_AT_INUM
	/*
	 * This is to prevent to have same ibase on both of from and into
	 * FIXME: we would want to split at better position.
	 */
	if (hint == ibase(leaf))
		hint++;

	trace("split at inum 0x%Lx", (L)hint);
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

static int ileaf_merge(struct btree *btree, void *vinto, void *vfrom)
{
	struct ileaf *into = vinto, *from = vfrom;
	unsigned fromcount = icount(from);

	/* If "from" is empty, does nothing */
	if (!fromcount)
		return 1;

	assert(ibase(from) > ibase(into));
	tuxkey_t fromibase = ibase(from);
	unsigned count = icount(into);
	int hole = fromibase - ibase(into) + count;

	be_u16 *dict = ileaf_dict(btree, into);
	be_u16 *fromdict = ileaf_dict(btree, from);
	int need_size = hole * sizeof(*dict) + ileaf_need(btree, from);

	if (ileaf_free(btree, into) < need_size)
		return 0;

	/* Fill hole of dict until from_ibase */
	unsigned limit = atdict(dict, count);
	be_u16 __limit = to_be_u16(limit);
	while (hole--) {
		count++;
		*(dict - count) = __limit;
	}

	/* Copy data from "from" */
	unsigned fromlimit = atdict(fromdict, fromcount);
	memcpy(into->table + limit, from->table, fromlimit);

	/* Adjust copying fromdict */
	if (limit) {
		int i;
		for (i = 1; i <= fromcount; i++)
			add_idict(dict - i, limit);
	}
	veccopy(dict - count - fromcount, fromdict - fromcount, fromcount);

	into->count = to_be_u16(count + fromcount);

	return 1;
}

inum_t find_empty_inode(struct btree *btree, struct ileaf *leaf, inum_t goal)
{
	assert(goal >= ibase(leaf));
	if (goal - ibase(leaf) >= btree->entries_per_leaf)
		return goal;
	unsigned at = goal - ibase(leaf);

	if (at < icount(leaf)) {
		be_u16 *dict = ileaf_dict(btree, leaf);
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
	be_u16 *dict = ileaf_dict(btree, ileaf);
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

/*
 * Chop inums
 * return value:
 * < 0 - error
 *   1 - modified
 *   0 - not modified
 */
static int ileaf_chop(struct btree *btree, tuxkey_t start, u64 len, void *leaf)
{
	struct ileaf *ileaf = leaf;
	be_u16 *dict = ileaf_dict(btree, leaf);
	tuxkey_t base = ibase(ileaf);
	unsigned count = icount(ileaf);
	unsigned at = start - base;
	void *startp, *endp, *tailp;
	unsigned size;

	if (at + 1 > count)
		return 0;

	len = min_t(u64, len, count - at);

	startp = ileaf->table + atdict(dict, at);
	endp = ileaf->table + atdict(dict, at + len);
	if (startp == endp)
		return 0;

	/* Remove data */
	tailp = ileaf->table + atdict(dict, count);
	memmove(startp, endp, tailp - endp);

	/* Adjust dict */
	size = endp - startp;
	while (at < count) {
		at++;
		add_idict(dict - at, -size);
	}

	ileaf_trim(btree, leaf);

	return 1;
}

static void *ileaf_resize(struct btree *btree, tuxkey_t inum, void *vleaf,
			  unsigned newsize)
{
	struct ileaf *ileaf = vleaf;
	be_u16 *dict = ileaf_dict(btree, ileaf);
	unsigned count = icount(ileaf);
	unsigned at = inum - ibase(ileaf);
	int extend_dict, offset, size;

	assert(inum >= ibase(ileaf));

	/*
	 * Restrict number of inum on a leaf.
	 * FIXME: we might want more flexible format.
	 */
	if (at >= btree->entries_per_leaf)
		return NULL;

	/* Get existent attributes, and calculate expand/shrink size */
	if (at + 1 > count) {
		/* Need to extend dict */
		extend_dict = (at + 1 - count) * sizeof(*dict);
		offset = atdict(dict, count);
		size = 0;
	} else {
		/* "at" is in dict, so get attr size */
		extend_dict = 0;
		offset = atdict(dict, at);
		size = __atdict(dict, at + 1) - offset;
	}

	if (ileaf_free(btree, ileaf) < (int)newsize - size + extend_dict)
		return NULL;

	/* Extend dict */
	if (extend_dict) {
		be_u16 limit = to_be_u16(atdict(dict, count));
		while (count < at + 1) {
			count++;
			*(dict - count) = limit;
		}
		ileaf->count = to_be_u16(count);
	}

	void *attrs = ileaf->table + offset;
	if (newsize != size) {
		/* Expand/Shrink attr space */
		unsigned limit = __atdict(dict, count);
		assert(limit >= offset + size);
		memmove(attrs + newsize, attrs + size, limit - offset - size);

		/* Adjust dict */
		int diff = newsize - size;
		at++;
		while (at <= count) {
			add_idict(dict - at, diff);
			at++;
		}
	}

	return attrs;
}

static int ileaf_write(struct btree *btree, tuxkey_t key_bottom,
		       tuxkey_t key_limit,
		       void *leaf, struct btree_key_range *key,
		       tuxkey_t *split_hint)
{
	struct ileaf_req *rq = container_of(key, struct ileaf_req, key);
	struct ileaf_attr_ops *attr_ops = btree->ops->private_ops;
	struct ileaf *ileaf = leaf;
	void *attrs;
	int size;

	assert(key->len == 1);

	size = attr_ops->encoded_size(btree, rq->data);
	assert(size);

	attrs = ileaf_resize(btree, key->start, ileaf, size);
	if (attrs == NULL) {
		/* There is no space to store */
		unsigned at = icount(ileaf) / 2;
		/* split at middle of inums. FIXME: better split position? */
		*split_hint = ibase(ileaf) + at;
		return -ENOSPC;
	}

	attr_ops->encode(btree, rq->data, attrs, size);

	key->start++;
	key->len--;

	return 0;
}

struct btree_ops itable_ops = {
	.btree_init	= ileaf_btree_init,
	.leaf_init	= ileaf_init,
	.leaf_split	= ileaf_split,
	.leaf_merge	= ileaf_merge,
	.leaf_resize	= ileaf_resize,
	.leaf_chop	= ileaf_chop,
	.leaf_write	= ileaf_write,
	.balloc		= balloc,
	.private_ops	= &iattr_ops,

	.leaf_sniff	= ileaf_sniff,
	.leaf_dump	= ileaf_dump,
};
