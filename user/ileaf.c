/*
 * Inode table btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef __KERNEL__
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "hexdump.c"
#define iattr_included_from_ileaf
#include "iattr.c"
#endif

#include "tux3.h"

struct ileaf { be_u16 magic, count; u32 pad; be_u64 ibase; char table[]; };

/*
 * inode leaf format
 *
 * A leaf has a small header followed by a table of attributes.  A vector of
 * offsets within the block grows down from the top of the leaf towards the
 * top of the attribute table, indexed by the difference between inum and
 * leaf->ibase, the base inum of the table block.
 */

static inline unsigned atdict(be_u16 *dict, unsigned at)
{
	return at ? from_be_u16(*(dict - at)) : 0;
}

static inline void add_idict(be_u16 *dict, int n)
{
	*dict = to_be_u16(from_be_u16(*dict) + n);
}

static inline struct ileaf *to_ileaf(vleaf *leaf)
{
	return leaf;
}

static inline unsigned icount(struct ileaf *leaf)
{
	return from_be_u16(leaf->count);
}

static inline tuxkey_t ibase(struct ileaf *leaf)
{
	return from_be_u64(leaf->ibase);
}

int ileaf_init(BTREE, vleaf *leaf)
{
	printf("initialize inode leaf %p\n", leaf);
	*(struct ileaf *)leaf = (struct ileaf){ to_be_u16(0x90de) };
	return 0;
}

int ileaf_sniff(BTREE, vleaf *leaf)
{
	return ((struct ileaf *)leaf)->magic == to_be_u16(0x90de);
}

unsigned ileaf_need(BTREE, vleaf *vleaf)
{
	be_u16 *dict = vleaf + btree->sb->blocksize;
	unsigned count = icount(to_ileaf(vleaf));
	return atdict(dict, count) + count * sizeof(*dict);
}

unsigned ileaf_free(BTREE, vleaf *leaf)
{
	return btree->sb->blocksize - ileaf_need(btree, leaf) - sizeof(struct ileaf);
}

void ileaf_dump(BTREE, vleaf *vleaf)
{
	SB = btree->sb;
	struct ileaf *leaf = vleaf;
	inum_t inum = ibase(leaf);
	be_u16 *dict = vleaf + sb->blocksize;
	unsigned offset = 0;
	printf("inode table block 0x%Lx/%i (%x bytes free)\n", (L)ibase(leaf), icount(leaf), ileaf_free(btree, leaf));
	//hexdump(dict - icount(leaf), icount(leaf) * 2);
	for (int i = -1; -i <= icount(leaf); i--, inum++) {
		int limit = from_be_u16(dict[i]), size = limit - offset;
		if (!size)
			continue;
		printf("  0x%Lx: ", (L)inum);
		//printf("[%x] ", offset);
		if (size < 0)
			printf("<corrupt>\n");
		else if (!size)
			printf("<empty>\n");
		else {
#ifndef main
			hexdump(leaf->table + offset, size);
#else
			struct inode inode = { .i_sb = btree->sb, .xcache = new_xcache(9999) };
			decode_attrs(&inode, leaf->table + offset, size);
			dump_attrs(&inode);
			xcache_dump(&inode);
			free(inode.xcache);
#endif
		}
		offset = limit;
	}
}

void *ileaf_lookup(BTREE, inum_t inum, struct ileaf *leaf, unsigned *result)
{
	assert(inum >= ibase(leaf));
	assert(inum < ibase(leaf) + btree->entries_per_leaf);
	unsigned at = inum - ibase(leaf), size = 0;
	void *attrs = NULL;
	printf("lookup inode 0x%Lx, %Lx + %x\n", (L)inum, (L)ibase(leaf), at);
	if (at < icount(leaf)) {
		be_u16 *dict = (void *)leaf + btree->sb->blocksize;
		unsigned offset = atdict(dict, at);
		if ((size = from_be_u16(*(dict - at - 1)) - offset))
			attrs = leaf->table + offset;
	}
	*result = size;
	return attrs;
}

int isinorder(BTREE, struct ileaf *leaf)
{
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	for (int i = 0, offset = 0, limit; --i >= -icount(leaf); offset = limit)
		if ((limit = from_be_u16(dict[i])) < offset)
			return 0;
	return 1;
}

int ileaf_check(BTREE, struct ileaf *leaf)
{
	char *why;
	why = "not an inode table leaf";
	if (leaf->magic != to_be_u16(0x90de))
		goto eek;
	why = "dict out of order";
	if (!isinorder(btree, leaf))
		goto eek;
	return 0;
eek:
	printf("%s!\n", why);
	return -1;
}

void ileaf_trim(BTREE, struct ileaf *leaf) {
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	while (icount(leaf) > 1 && *(dict - icount(leaf)) == *(dict - icount(leaf) + 1))
		leaf->count = to_be_u16(from_be_u16(leaf->count) - 1);
	if (icount(leaf) == 1 && !*(dict - 1))
		leaf->count = 0;
}

#define SPLIT_AT_INUM

tuxkey_t ileaf_split(BTREE, tuxkey_t inum, vleaf *from, vleaf *into)
{
	assert(ileaf_sniff(btree, from));
	struct ileaf *leaf = from, *dest = into;
	be_u16 *dict = from + btree->sb->blocksize, *destdict = into + btree->sb->blocksize;

#ifdef SPLIT_AT_INUM
	printf("split at inum 0x%Lx\n", (L)inum);
	assert(inum >= ibase(leaf));
	unsigned at = inum - ibase(leaf) < icount(leaf) ? inum - ibase(leaf) : icount(leaf);
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
	unsigned split = atdict(dict, at), free = from_be_u16(*(dict - icount(leaf)));
	printf("split at %x of %x\n", at, icount(leaf));
	printf("copy out %x bytes at %x\n", free - split, split);
	assert(free >= split);
	memcpy(dest->table, leaf->table + split, free - split);
	dest->count = to_be_u16(icount(leaf) - at);
	veccopy(destdict - icount(dest), dict - icount(leaf), icount(dest));
	for (int i = 1; i <= icount(dest); i++)
		add_idict(destdict - i, -split);
#ifdef SPLIT_AT_INUM
	/* round down to multiple of 64 above ibase */
	inum_t round = inum & ~(inum_t)(btree->entries_per_leaf - 1);
	dest->ibase = to_be_u64(round > ibase(leaf) + icount(leaf) ? round : inum);
#else
	dest->ibase = to_be_u64(ibase(leaf) + at);
#endif
	leaf->count = to_be_u16(at);
	memset(leaf->table + split, 0, (char *)(dict - icount(leaf)) - (leaf->table + split));
	ileaf_trim(btree, leaf);
	return ibase(dest);
}

void ileaf_merge(BTREE, struct ileaf *leaf, struct ileaf *from)
{
	if (!icount(from))
		return;
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	be_u16 *fromdict = (void *)from + btree->sb->blocksize;
	unsigned at = icount(leaf), free = atdict(dict, at), size = atdict(fromdict, icount(from));
	printf("copy in %i bytes\n", size);
	memcpy(leaf->table + free, from->table, size);
	leaf->count = to_be_u16(from_be_u16(leaf->count) + icount(from));
	veccopy(dict - icount(leaf), fromdict - icount(from), icount(from));
	for (int i = at + 1; at && i <= at + icount(from); i++)
		add_idict(dict - i, from_be_u16(*(dict - at)));
}

void *ileaf_resize(BTREE, tuxkey_t inum, vleaf *base, unsigned newsize)
{
	assert(ileaf_sniff(btree, base));
	struct ileaf *leaf = base;
	assert(inum >= ibase(leaf));
	be_u16 *dict = base + btree->sb->blocksize;

	unsigned at = inum - ibase(leaf);
	if (at >= btree->entries_per_leaf)
		return NULL;

	unsigned extend_empty = at < icount(leaf) ? 0 : at - icount(leaf) + 1;
	unsigned offset = at && icount(leaf) ? from_be_u16(*(dict - (at < icount(leaf) ? at : icount(leaf)))) : 0;
	unsigned size = at < icount(leaf) ? from_be_u16(*(dict - at - 1)) - offset : 0;
	int more = newsize - size;
	if (more > 0 && sizeof(*dict) * extend_empty + more > ileaf_free(btree, leaf))
		return NULL;
	for (; extend_empty--; leaf->count = to_be_u16(from_be_u16(leaf->count) + 1))
		*(dict - icount(leaf) - 1) = to_be_u16(atdict(dict, icount(leaf)));
	assert(icount(leaf));
	unsigned itop = from_be_u16(*(dict - icount(leaf)));
	void *attrs = leaf->table + offset;
	printf("resize inum 0x%Lx at 0x%x from %x to %x\n", (L)inum, offset, size, newsize);

	assert(itop >= offset + size);
	memmove(attrs + newsize, attrs + size, itop - offset - size);
	for (int i = at + 1; i <= icount(leaf); i++)
		add_idict(dict - i, more);
	return attrs;
}

inum_t find_empty_inode(BTREE, struct ileaf *leaf, inum_t goal)
{
	assert(goal >= ibase(leaf));
	goal -= ibase(leaf);
	//printf("find empty inode starting at %Lx, base %Lx\n", (L)goal, (L)ibase(leaf));
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	unsigned i, offset = goal && goal < icount(leaf) ? from_be_u16(*(dict - goal)) : 0;
	for (i = goal; i < icount(leaf); i++) {
		unsigned limit = from_be_u16(*(dict - i - 1));
		if (offset == limit)
			break;
		offset = limit;
	}
	return i + ibase(leaf);
}

int ileaf_purge(BTREE, inum_t inum, struct ileaf *leaf)
{
	if (inum < ibase(leaf) || inum - ibase(leaf) >= btree->entries_per_leaf)
		return -EINVAL;
	be_u16 *dict = (void *)leaf + btree->sb->blocksize;
	unsigned at = inum - ibase(leaf);
	unsigned offset = atdict(dict, at);
	unsigned size = from_be_u16(*(dict - at - 1)) - offset;
	printf("delete inode %Lx from %p[%x/%x]\n", (L)inum, leaf, at, size);
	if (!size)
		return -ENOENT;
	unsigned free = from_be_u16(*(dict - icount(leaf))), tail = free - offset - size;
	assert(offset + size + tail <= free);
	memmove(leaf->table + offset, leaf->table + offset + size, tail);
	for (int i = at + 1; i <= icount(leaf); i++)
		add_idict(dict - i, -size);
	ileaf_trim(btree, leaf);
	return 0;
}

struct btree_ops itable_ops = {
	.leaf_dump = ileaf_dump,
	.leaf_sniff = ileaf_sniff,
	.leaf_init = ileaf_init,
	.leaf_split = ileaf_split,
	.leaf_resize = ileaf_resize,
	.balloc = balloc,
};

#ifndef __KERNEL__
#ifndef main
struct ileaf *ileaf_create(BTREE)
{
	struct ileaf *leaf = malloc(btree->sb->blocksize);
	ileaf_init(btree, leaf);
	return leaf;
}

void ileaf_destroy(BTREE, struct ileaf *leaf)
{
	assert(ileaf_sniff(btree, leaf));
	free(leaf);
}

void test_append(BTREE, struct ileaf *leaf, inum_t inum, int more, char fill)
{
	unsigned size = 0;
	char *attrs = ileaf_lookup(btree, inum, leaf, &size);
	printf("attrs size = %i\n", size);
	attrs = ileaf_resize(btree, inum, leaf, size + more);
	memset(attrs + size, fill, more);
}

void test_remove(BTREE, struct ileaf *leaf, inum_t inum, int less)
{
	unsigned size = 0;
	char *attrs = ileaf_lookup(btree, inum, leaf, &size);
	printf("attrs size = %i\n", size);
	attrs = ileaf_resize(btree, inum, leaf, size - less);
}

block_t balloc(SB)
{
	return sb->nextalloc++;
}

int main(int argc, char *argv[])
{
	printf("--- test inode table leaf methods ---\n");
	SB = &(struct sb){ .blocksize = 4096 };
	struct btree *btree = &(struct btree){ .sb = sb, .ops = &itable_ops };
	btree->entries_per_leaf = 64; // !!! should depend on blocksize
	struct ileaf *leaf = ileaf_create(btree);
	struct ileaf *dest = ileaf_create(btree);
	leaf->ibase = to_be_u64(0x10);
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x13, 2, 'a');
	test_append(btree, leaf, 0x14, 4, 'b');
	test_append(btree, leaf, 0x16, 6, 'c');
	ileaf_dump(btree, leaf);
	ileaf_split(btree, 0x10, leaf, dest);
	ileaf_dump(btree, leaf);
	ileaf_dump(btree, dest);
	ileaf_merge(btree, leaf, dest);
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x13, 3, 'x');
	ileaf_dump(btree, leaf);
	test_append(btree, leaf, 0x18, 3, 'y');
	ileaf_dump(btree, leaf);
	test_remove(btree, leaf, 0x16, 5);
	ileaf_dump(btree, leaf);
	unsigned size = 0;
	char *inode = ileaf_lookup(btree, 0x13, leaf, &size);
	hexdump(inode, size);
	for (int i = 0x11; i <= 0x20; i++)
		printf("goal 0x%x => 0x%Lx\n", i, (L)find_empty_inode(btree, leaf, i));
	ileaf_purge(btree, 0x14, leaf);
	ileaf_purge(btree, 0x18, leaf);
hexdump(leaf, 16);
	ileaf_check(btree, leaf);
	ileaf_dump(btree, leaf);
	ileaf_destroy(btree, leaf);
	ileaf_destroy(btree, dest);
	return 0;
}
#endif
#endif /* !__KERNEL__ */
