/*
 * File index btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "hexdump.c"
#include "trace.h"
#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

struct extent { u64 block:48, count_field:6, version:10; };
struct group { u32 count:8, keyhi:24; };
struct entry { u32 limit:8, keylo:24; };
struct dleaf { u16 magic, free, used, groups; struct extent table[]; };

struct extent make_extent(block_t block, unsigned count)
{
	return (struct extent){ .block = block, .count_field = count - 1 };
}

static inline unsigned extent_count(struct extent extent)
{
	return extent.count_field + 1;
}

static inline unsigned extent_block(struct extent extent)
{
	return extent.block;
}

/*
 * Leaf index format
 *
 * A leaf has a small header followed by a table of extents.  A two level
 * index grows down from the top of the leaf towards the top of the extent
 * table.  The index maps each unique logical address in the leaf to one or
 * more extents beginning at that address.
 *
 * The top level index is a table of groups of entries all having the same
 * high 24 bits of logical address which is only stored once, along with the
 * 8 bit count of entries in the group.  Since there can be more than 256
 * entries at the same logical address, there could be more than one group
 * with the same logical address.  The group count is used both to know the
 * number of entries in the group and to find the beginning of the entry table
 * for a given group, by adding up the sizes of the proceeding groups.
 *
 * The 8 bit entry limit limits the number of different versions at the same
 * logical address to 255.  For now.
 *
 * The second level entry tables are stored end to end in reverse immediately
 * below the groups table, also stored in reverse.  Each entry has the low 24
 * bits of the logical address and the 8 bit 'limit' offset of the last extent
 * for that logical address, measuring from the first extent for the group in
 * units of extent size.  The limit is used rather than an offset so that the
 * final offset is the count of extents in the group, which is summed up to
 * locate the first extent for the group in the extent table.  The difference
 * between and entry limit and the limit of its predecessor gives the count of
 * extents for the logical address specified by the entry.
 *
 * At the top level of a very large or very sparse btree it is likely that the
 * group table will be relatively larger, up to the same size as all the entry
 * tables.  This does not matter much in terms of overall btree bulk.  A few
 * levels down the logical address space will have been split to the point
 * where most entries in a leaf fit into one entry table.
 *
 * This leaf indexing scheme has some obscure boundary conditions, such as
 * the zeroth entry of a group having no predecessor and thus needing to have
 * a special check to supply zero as the preceding limit.  Inserting and
 * deleting are fairly involved and subtle.  But the space required to index
 * extents in a deep btree is reduced considerably, which is compelling.  In
 * the end, the indexing scheme provides access to a simple linear table of
 * extents and a count, so there is little impact on the specialized methods
 * that operate on those extents due to the complexity of the indexing scheme.
 * The lookup operation on this index is very efficient.  Each level of the
 * index is suited to binary search.  A sequence of inserts in ascending order
 * in the same group requires no existing entries to be relocated, the reason
 * the entry list is stored in reverse.
 */

static inline struct dleaf *to_dleaf(vleaf *leaf)
{
	return leaf;
}

int dleaf_init(BTREE, vleaf *leaf)
{
	if (!leaf)
		return -1;
	*to_dleaf(leaf) = (struct dleaf){ .magic = 0x1eaf, .free = sizeof(struct dleaf), .used = btree->sb->blocksize };
	return 0;
}

struct dleaf *leaf_create(BTREE)
{
	struct dleaf *leaf = malloc(btree->sb->blocksize);
	dleaf_init(btree, leaf);
	return leaf;
}

int dleaf_sniff(BTREE, vleaf *leaf)
{
	return (to_dleaf(leaf))->magic == 0x1eaf;
}

void dleaf_destroy(BTREE, struct dleaf *leaf)
{
	assert(dleaf_sniff(btree, leaf));
	free(leaf);
}

unsigned dleaf_free(BTREE, vleaf *leaf)
{
	return to_dleaf(leaf)->used - to_dleaf(leaf)->free;
}

unsigned dleaf_need(BTREE, struct dleaf *leaf)
{
	return btree->sb->blocksize - dleaf_free(btree, leaf) - sizeof(struct dleaf);
}

int dleaf_free2(BTREE, void *vleaf)
{
	struct dleaf *leaf = vleaf;
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *gstop = gdict - leaf->groups;
	struct entry *edict = (void *)gstop, *entry = edict;
	struct extent *extents = leaf->table;
	for (struct group *group = gdict; group-- > gstop;)
		extents += (entry -= group->count)->limit;
	return (void *)entry - (void *)extents;
}

void dleaf_dump(BTREE, vleaf *vleaf)
{
	unsigned blocksize = btree->sb->blocksize;
	struct dleaf *leaf = vleaf;
	struct group *groups = (void *)leaf + blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1), *entry = entries;
	struct extent *extents = leaf->table;

	printf("%i entry groups:\n", leaf->groups);
	for (struct group *group = groups; group > grbase; group--) {
		printf("  %ti/%i:", groups - group, group->count);
		//printf(" [%i]", extents - leaf->table);
		struct entry *enbase = entry - group->count;
		while (entry > enbase) {
			--entry;
			unsigned offset = entry == entries - 1 ? 0 : (entry + 1)->limit;
			int count = entry->limit - offset;
			printf(" %Lx =>", ((L)group->keyhi << 24) + entry->keylo);
			//printf(" %p (%i)", entry, entry->limit);
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++) {
				struct extent extent = extents[offset + i];
				printf(" %Lx", (L)extent.block);
				if (extent_count(extent))
					printf("/%x", extent_count(extent));
			}
			//printf(" {%u}", entry->limit);
			printf(";");
		}
		printf("\n");
		entries -= group->count;
		extents += entry->limit;
	}
}

/*
 * Reasons this dleaf truncator sucks:
 *
 * * Does not check for integrity at all so a corrupted leaf can cause overflow
 *   and system corruption.
 *
 * * Assumes all block pointers after the truncation point will be deleted,
 *   which does not hold when versions arrive.
 *
 * * Modifies a group count in the middle of the traversal knowing that it has
 *   already loaded the changed field and will not load it again, fragile.
 *
 * * Does not provide a generic mechanism that can be adapted to other
 *   truncation tasks.
 *
 * But it does truncate so it is getting checked in just for now.
 */

int dleaf_chop(BTREE, tuxkey_t chop, vleaf *vleaf)
{
	struct dleaf *leaf = vleaf;
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *group = gdict;
	struct entry *entry = (void *)(--group - leaf->groups);
	struct group *gstop = group - leaf->groups;
	struct entry *estop = entry - group->count;
	unsigned extents = 0, start = 0, trunc = 0;
	unsigned newgroups = leaf->groups;

	if (!newgroups)
		return 0;

	while (1) {
		unsigned count = entry->limit - start;
		tuxkey_t key = ((tuxkey_t)group->keyhi << 24) | entry->keylo;
		if (key >= chop) {
			if (!trunc) {
				unsigned newcount = group->count - (entry - estop);
				newgroups = gdict - group - !newcount;
				group->count = newcount;
				trunc = 1;
			}
			for (int i = 0; i < count; i++)
				(btree->ops->bfree)(btree->sb, leaf->table[extents + i].block);
		}
		start = entry->limit;
		extents += count;
		if (--entry != estop)
			continue;
		if (--group == gstop)
			break;
		estop = entry - group->count;
		start = 0;
	}
	unsigned tamp = (leaf->groups - newgroups) * sizeof(struct group);
	unsigned tail = (void *)(gdict - newgroups) - ((void *)entry + tamp);
	memmove((void *)entry + tamp, entry, tail);
	leaf->groups = newgroups;
	return 0;
}

struct dwalk {
	struct dleaf *leaf;
	struct group *group, *gstop, *gdict;
	struct entry *entry, *estop;
	struct extent *exbase, *extent, *exstop;
	struct {
		struct group group;
		struct entry entry;
		int used, free, groups;
	} mock;
};

int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key)
{
	trace("probe for 0x%Lx", (L)key);
	unsigned keylo = key & 0xffffff, keyhi = key >> 24;
	struct group *gdict = (void *)leaf + blocksize;
	struct entry *edict = (struct entry *)(gdict - leaf->groups);
	struct group *gstop = gdict - leaf->groups, *group = gdict;
	struct entry *estop = edict, *entry;
	struct extent *exbase = leaf->table;

	if (leaf->groups)
		while (--group >= gstop) {
			trace_off("group %i check %x = %x", gdict - group - 1, keyhi, group->keyhi);
			estop -= group->count;
			if (group->keyhi > keyhi)
				break;
			trace_off("next group keylow = %x", (estop - 1)->keylo);
			if (group->keyhi == keyhi) {
				if (group == gstop)
					break;
				if ((group - 1)->keyhi != keyhi)
					break;
				if ((estop - 1)->keylo > keylo)
					break;
			}
			exbase += estop->limit;
		}

	struct extent *extent = exbase, *exstop = exbase;
	//trace("group %i entry %i of %i", gdict - 1 - group, estop + group->count - 1 - entry, group->count);
	if (!leaf->groups || group < gstop)
		entry = estop;
	else {
		assert(group->keyhi >= keyhi);
		entry = estop + group->count;
		//trace("entry %x, estop %x", entry->keylo, estop->keylo);
		if (group->keyhi == keyhi) {
			while (entry > estop) {
				--entry;
				trace_off("entry check %x, %x", keylo, (entry - 1)->keylo);
				exstop = exbase + entry->limit;
				if (entry->keylo >= keylo)
					break;
				extent = exstop;
			}
		}
	}

	trace_off("group %i entry %i of %i", gdict - 1 - group, estop + group->count - 1 - entry, group->count);
	trace("extent = %tx, exstop = %tx", extent - leaf->table, exstop - leaf->table);
	*walk = (struct dwalk){
		.leaf = leaf, .gdict = gdict,
		.group = group, .gstop = gstop,
		.entry = entry, .estop = estop,
		.extent = extent, .exstop = exstop,
		.exbase = exbase };
	return 0;
}

tuxkey_t dwalk_index(struct dwalk *walk)
{
	return (walk->group->keyhi << 24) | walk->entry->keylo;
}

struct extent *dwalk_next(struct dwalk *walk)
{
	if (!walk->leaf->groups)
		return NULL;
	trace("walk extent = %tx, exstop = %tx", walk->extent - walk->leaf->table, walk->exstop - walk->leaf->table);
	if (walk->extent >= walk->exstop) {
		trace("at entry %i/%i", walk->estop + walk->group->count - 1 - walk->entry, walk->group->count);
		if (walk->entry <= walk->estop) {
			trace("next group, end = %i", walk->group <= walk->gstop);
			if (walk->group <= walk->gstop)
				return NULL;
			walk->exbase += walk->estop->limit;
			trace("exbase => %Lx", (L)walk->exbase->block);
			trace("extent => %Lx", (L)walk->extent->block);
			walk->estop -= (--walk->group)->count;
		}
		walk->entry--;
		walk->exstop = walk->exbase + walk->entry->limit;
	}
	trace("next extent 0x%Lx => %Lx/%x", dwalk_index(walk), (L)walk->extent->block, extent_count(*walk->extent));
	trace("walk extent = %tx, exstop = %tx", walk->extent - walk->leaf->table, walk->exstop - walk->leaf->table);
	trace("at entry %i/%i", walk->estop + walk->group->count - 1 - walk->entry, walk->group->count);
	return walk->extent++; // also return key
}

void dwalk_back(struct dwalk *walk)
{
	trace("back one entry");
	if (++walk->entry == walk->estop + walk->group->count) {
		trace("back one group");
		if (++walk->group == walk->gdict) {
			trace("at start");
			--walk->group;
			walk->exstop = walk->extent = walk->exbase = walk->leaf->table;
			return;
		}
		walk->exbase -= walk->entry->limit;
		walk->estop = walk->entry;
		trace("exbase => %Lx", (L)walk->exbase->block);
		trace("entry offset = %i", walk->estop + walk->group->count - 1 - walk->entry);
	}
	walk->extent = walk->exbase + (walk->estop + walk->group->count - 1 - walk->entry);
	walk->exstop = walk->exbase + walk->entry->limit;
	trace("exstop => %Lx", (L)walk->exstop->block);
}

void dwalk_chop_after(struct dwalk *walk)
{
	struct dleaf *leaf = walk->leaf;
	struct group *gdict = walk->gdict;
	struct entry *ebase = walk->estop + walk->group->count;
	struct entry *entry = walk->entry;
	unsigned newgroups = walk->gdict - walk->group;
	walk->group->count = ebase - entry;
	trace_on("%i groups, %i entries in last", leaf->groups, walk->group->count);
	void *free = (void *)entry + (leaf->groups - newgroups) * sizeof(*gdict);
	memmove(free, entry, (void *)(gdict - newgroups) - free);
	walk->estop = walk->entry = free;
	walk->gstop = walk->group;
	leaf->groups = newgroups;
}

void dwalk_chop(struct dwalk *walk) // do we ever need this?
{
	if (!walk->leaf->groups) {
		trace("<<<<<<<<<<<<< dleaf empty");
		return;
	}
	if (walk->group + 1 == walk->gdict && walk->entry + 1 == walk->estop + walk->group->count) {
		trace(">>>>>>>>>>>>> empty dleaf");
		walk->leaf->groups = 0;
		return;
	}
	dwalk_back(walk);
	dwalk_chop_after(walk);
}

#ifndef main
#define MAX_GROUP_ENTRIES 7
#else
#define MAX_GROUP_ENTRIES 255
#endif

int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct extent extent)
{
	if (!walk->leaf->groups || walk->entry == walk->estop || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!walk->mock.groups || walk->mock.group.keyhi != keyhi || walk->mock.group.count >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->mock.groups);
			walk->exbase += walk->mock.entry.limit;
			walk->mock.group = (struct group){ .keyhi = keyhi };
			walk->mock.used -= sizeof(struct group);
			walk->mock.groups++;
		}
		walk->mock.used -= sizeof(struct entry);
		walk->mock.entry = (struct entry){ .keylo = keylo, .limit = walk->extent - walk->exbase };
		walk->mock.group.count++;
	}
	trace("add extent 0x%Lx => 0x%Lx/%x", (L)index, (L)extent.block, extent_count(extent));
	walk->mock.free += sizeof(*walk->extent);
	walk->extent++;
	walk->mock.entry.limit++;
	return 0;
}

int dwalk_pack(struct dwalk *walk, tuxkey_t index, struct extent extent)
{
	printf("group %ti/%i ", walk->gstop + walk->leaf->groups - 1 - walk->group, walk->leaf->groups);
	//printf("at entry %ti/%i\n", walk->estop + walk->group->count - 1 - walk->entry, walk->group->count);
	if (!walk->leaf->groups || walk->entry == walk->estop || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!walk->leaf->groups || walk->group->keyhi != keyhi || walk->group->count >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->leaf->groups);
			/* will it fit? */
			assert(sizeof(struct entry) == sizeof(struct group));
			assert(walk->leaf->free <= walk->leaf->used - sizeof(*walk->entry));
			/* move entries down, adjust walk state */
			/* could preplan this to avoid move: need additional pack state */
			vecmove(walk->entry - 1, walk->entry, (struct entry *)walk->group - walk->entry);
			walk->entry--; /* adjust to moved position */
			walk->exbase += walk->leaf->groups ? walk->entry->limit : 0;
			*--walk->group = (struct group){ .keyhi = keyhi };
			walk->leaf->used -= sizeof(struct group);
			walk->leaf->groups++;
		}
		assert(walk->leaf->free <= walk->leaf->used - sizeof(*walk->entry));
		walk->leaf->used -= sizeof(struct entry);
		*--walk->entry = (struct entry){ .keylo = keylo, .limit = walk->extent - walk->exbase };
		walk->group->count++;
	}
	trace("add extent %i", walk->extent - walk->leaf->table);
	//trace("add extent 0x%Lx => 0x%Lx/%x", (L)index, (L)extent.block, extent_count(extent));
	assert(walk->leaf->free + sizeof(*walk->extent) <= walk->leaf->used);
	walk->leaf->free += sizeof(*walk->extent);
	*walk->extent++ = extent;
	walk->entry->limit++;
	return 0; // extent out of order??? leaf full???
}

int dleaf_check(BTREE, struct dleaf *leaf)
{
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *gstop = gdict - leaf->groups;
	struct entry *edict = (void *)gstop, *entry = edict;
	struct extent *extents = leaf->table;
	unsigned excount = 0, encount = 0;
	char *why;

	for (struct group *group = gdict - 1; group >= gstop; group--) {
		entry -= group->count;
		excount += entry->limit;
		encount += group->count;
	}
	//printf("encount = %i, excount = %i, \n", encount, excount);
	why = "used count wrong";
	if (leaf->used != (void *)(edict - encount) - (void *)leaf)
		goto eek;
	why = "free count wrong";
	if (leaf->free != (void *)(extents + excount) - (void *)leaf)
		goto eek;
	why = "free check mismatch";
	if (leaf->used - leaf->free != dleaf_free2(btree, leaf))
		goto eek;
	return 0;
eek:
	printf("free %i, used %i\n", leaf->free, leaf->used);
	printf("%s!\n", why);
	return -1;
}

tuxkey_t dleaf_split(BTREE, tuxkey_t key, vleaf *from, vleaf *into)
{
	assert(dleaf_sniff(btree, from));
	struct dleaf *leaf = from, *dest = into;
	struct group *groups = from + btree->sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	printf("split %p into %p\n", leaf, dest);
	unsigned encount = 0, recount = 0, grsplit = 0, exsplit = 0;

	/* find middle in terms of entries - may be unbalanced in extents */
	for (struct group *group = groups - 1; group >= grbase; group--)
		encount += group->count;
	unsigned split = encount / 2;
	for (struct group *group = groups - 1; group >= grbase; group--, grsplit++) {
		if (recount + group->count > split)
			break;
		entries -= group->count;
		exsplit += entries->limit;
		recount += group->count;
	}

	/* have to split a group? */
	unsigned cut = split - recount;
	if (cut)
		exsplit += (entries - cut)->limit;
	entries = (void *)grbase; /* restore it */
	printf("split %i entries at group %i, entry %x\n", encount, grsplit, cut);
	printf("split extents at %i\n", exsplit);
	/* copy extents */
	unsigned size = from + leaf->free - (void *)(leaf->table + exsplit);
	memcpy(dest->table, leaf->table + exsplit, size);

	/* copy groups */
	struct group *destgroups = (void *)dest + btree->sb->blocksize;
	dest->groups = leaf->groups - grsplit;
	veccopy(destgroups - dest->groups, grbase, dest->groups);
	(destgroups - 1)->count -= cut;
	leaf->groups = grsplit + !!cut;
	grbase = groups - leaf->groups;
	if (cut)
		(groups - leaf->groups)->count = cut;

	/* copy entries */
	struct entry *destentries = (void *)(destgroups - dest->groups);
	struct entry *enbase = entries - encount;
	unsigned encopy = encount - split;
	veccopy(destentries - encopy, enbase, encopy);
	if (cut)
		for (int i = 1; i <= (destgroups - 1)->count; i++)
			(destentries - i)->limit -= (entries - split)->limit;
	vecmove(groups - leaf->groups - split, entries - split, split);

	/* clean up */
	leaf->free = (void *)(leaf->table + exsplit) - from;
	dest->free = (void *)leaf->table + size - from;
	leaf->used = (void *)(grbase - split) - from;
	dest->used = (void *)(groups - dest->groups - encount + split) - from;
	memset(from + leaf->free, 0, leaf->used - leaf->free);
	return ((destgroups - 1)->keyhi << 24) | (destentries - 1)->keylo;
}

void dleaf_merge(BTREE, struct dleaf *leaf, struct dleaf *from)
{
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	printf("merge %p into %p\n", from, leaf);
	//assert(dleaf_need(from) <= dleaf_free(leaf));

	/* append extents */
	unsigned size = from->free - sizeof(struct dleaf);
	memcpy((void *)leaf + leaf->free, from->table, size);
	leaf->free += size;

	/* merge last group (lowest) with first of from (highest)? */
	struct group *fromgroups = (void *)from + btree->sb->blocksize;
	int uncut = leaf->groups && from->groups && ((fromgroups - 1)->keyhi == grbase->keyhi);

	/* make space and append groups except for possibly merged group */
	unsigned addgroups = from->groups - uncut;
	struct group *grfrom = fromgroups - from->groups;
	struct entry *enfrom = (void *)from + from->used;
	struct entry *enbase = (void *)leaf + leaf->used;
	vecmove(enbase - addgroups, enbase, entries - enbase);
	veccopy(grbase -= addgroups, grfrom, addgroups);
	enbase -= addgroups;
	if (uncut)
		(grbase + addgroups)->count += (fromgroups - 1)->count;
	leaf->groups += addgroups;

        /* append entries */
	size = (void *)grfrom - (void *)enfrom;
	memcpy((void *)enbase - size, enfrom, size);
	leaf->used = (void *)enbase - size - (void *)leaf;

	/* adjust entry limits for merged group */
	if (uncut)
		for (int i = 1; i <= (fromgroups - 1)->count; i++)
			(enbase - i)->limit += enbase->limit;
}

struct btree_ops dtree_ops = {
	.leaf_sniff = dleaf_sniff,
	.leaf_init = dleaf_init,
	.leaf_dump = dleaf_dump,
	.leaf_split = dleaf_split,
//	.leaf_resize = dleaf_resize,
	.leaf_chop = dleaf_chop,
	.balloc = balloc,
	.bfree = bfree,
};

#ifndef main
block_t balloc(SB)
{
	return sb->nextalloc++;
}

void bfree(SB, block_t block)
{
	printf(" free %Lx\n", (L)block);
}

void *dleaf_lookup(BTREE, struct dleaf *leaf, tuxkey_t index, unsigned *count)
{
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	struct extent *extents = leaf->table;
	unsigned keylo = index & 0xffffff, keyhi = index >> 24;

	for (struct group *group = groups - 1; group >= grbase; group--) {
		struct entry *enbase = entries - group->count;
		if (keyhi == group->keyhi)
			for (struct entry *entry = entries; entry > enbase;)
				if ((--entry)->keylo == keylo) {
					unsigned offset = entry - enbase == group->count - 1 ? 0 : (entry + 1)->limit;
					*count = entry->limit - offset;
					return extents + offset;
				}
		/* could fail out early here */
		extents += enbase->limit;
		entries -= group->count;
	}
	*count = 0;
	return NULL;
}

int main(int argc, char *argv[])
{
	printf("--- leaf test ---\n");
	SB = &(struct sb){ .blocksize = 1 << 10 };
	struct btree *btree = &(struct btree){ .sb = sb, .ops = &dtree_ops };
	struct dleaf *leaf = leaf_create(btree);
	dleaf_chop(btree, 0x14014LL, leaf);

	unsigned hi = 1 << 24, hi2 = 3 * hi/*, next = 0*/;
	unsigned keys[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, hi + 0x44, hi + 0x99 };
	struct dwalk *walk = &(struct dwalk){ };

	for (int i = 1; i < 2; i++) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x3000055);
		if ((walk->mock.groups = walk->leaf->groups)) {
			walk->mock.group = *walk->group;
			walk->mock.entry = *walk->entry;
		}
		int (*try)(struct dwalk *walk, tuxkey_t key, struct extent extent) = i ? dwalk_pack: dwalk_mock;
		try(walk, 0x3001001, (struct extent){ .block = 0x1 });
		try(walk, 0x3001002, (struct extent){ .block = 0x2 });
		try(walk, 0x3001003, (struct extent){ .block = 0x3 });
		try(walk, 0x3001004, (struct extent){ .block = 0x4 });
		try(walk, 0x3001005, (struct extent){ .block = 0x5 });
		try(walk, 0x3001006, (struct extent){ .block = 0x6 });
		if (!i) printf("mock free = %i, used = %i\n", walk->mock.free, walk->mock.used);
	}
	dleaf_dump(btree, leaf);
	dleaf_check(btree, leaf);
exit(0); // valgrind happiness
	if (1) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x1000044);
		dwalk_back(walk);
		dwalk_back(walk);
		for (struct extent *extent; (extent = dwalk_next(walk));)
			printf("0x%Lx => 0x%Lx\n", (L)dwalk_index(walk), (L)extent->block);
		return 0;
	}
	if (1) {
		dwalk_probe(leaf, sb->blocksize, walk, 0x1c01c);
		dwalk_chop(walk);
		dleaf_dump(btree, leaf);
		return 0;
	}
	dleaf_dump(btree, leaf);
	for (int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		unsigned key = keys[i];
		unsigned count;
		void *found = dleaf_lookup(btree, leaf, key, &count);
		if (count) {
			printf("lookup 0x%x, found [%i] ", key, count );
			hexdump(found, count);
		} else
			printf("0x%x not found\n", key);
	}

	struct dleaf *dest = leaf_create(btree);
	tuxkey_t key = dleaf_split(btree, 0, leaf, dest);
	printf("split key 0x%Lx\n", (L)key);
	dleaf_dump(btree, leaf);
	dleaf_dump(btree, dest);
	dleaf_merge(btree, leaf, dest);
	dleaf_dump(btree, leaf);
	dleaf_chop(btree, 0x14014LL, leaf);
	dleaf_dump(btree, leaf);
	dleaf_destroy(btree, leaf);
	dleaf_destroy(btree, dest);
	return 0;
}
#endif
