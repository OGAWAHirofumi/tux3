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
#define trace trace_off
#endif

struct extent { block_t block:48, count:6, version:10; };
struct group { u32 count:8, keyhi:24; };
struct entry { u32 limit:8, keylo:24; };
struct dleaf { u16 magic, free, used, groups; struct extent table[]; };

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

unsigned leaf_free(BTREE, vleaf *leaf)
{
	return to_dleaf(leaf)->used - to_dleaf(leaf)->free;
}

unsigned leaf_need(BTREE, struct dleaf *leaf)
{
	return btree->sb->blocksize - leaf_free(btree, leaf) - sizeof(struct dleaf);
}

void dleaf_dump(BTREE, vleaf *vleaf)
{
	struct dleaf *leaf = vleaf;
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = --groups - leaf->groups;
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
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++)
				printf(" %Lx", (L)(extents + offset + i)->block);
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

int dleaf_chop(BTREE, tuxkey_t high, vleaf *vleaf)
{
	struct dleaf *leaf = vleaf;
	struct group *group = (void *)leaf + btree->sb->blocksize, *top = group;
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
		if (key >= high) {
			if (!trunc) {
				unsigned newcount = group->count - (entry - estop);
				newgroups = top - group - !newcount;
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
	unsigned tamp = (leaf->groups - newgroups) * sizeof(*group);
	unsigned tail = (void *)(top - newgroups) - ((void *)entry + tamp);
	memmove((void *)entry + tamp, entry, tail);
	leaf->groups = newgroups;
	return 0;
}

struct dwalk {
	struct dleaf *leaf;
	struct group *group, *gstop;
	struct entry *entry, *estop;
	struct extent *exbase, *extent, *exstop;
	/* mock state */
	struct group mock_group;
	struct entry mock_entry;
	int used, free, groups;
};

int dwalk_probe(SB, struct dleaf *leaf, struct dwalk *walk, tuxkey_t key)
{
	unsigned keylo = key & 0xffffff, keyhi = key >> 24;
	struct group *gdict = (void *)leaf + sb->blocksize;
	struct entry *edict = (struct entry *)(gdict - leaf->groups);
	struct group *gstop = gdict - leaf->groups, *group = gdict - 1;
	struct entry *estop = edict - group->count, *entry;
	struct extent *exbase = leaf->table;

	while (1) {
		//printf("group check %x, %x\n", keyhi, group->keyhi);
		if (group->keyhi > keyhi)
			break;
		//printf("next group keylow = %x\n", (estop - 1)->keylo);
		if (group->keyhi == keyhi) {
			if (group == gstop)
				break;
			if ((group - 1)->keyhi != keyhi)
				break;
			if ((estop - 1)->keylo > keylo)
				break;
		}
		exbase += estop->limit;
		if (--group < gstop)
			break;
		estop -= group->count;
	}
	struct extent *extent = exbase, *exstop = exbase;
	if (group < gstop)
		entry = estop - 1;
	else {
		assert(group->keyhi >= keyhi);
		entry = estop + group->count - 1;
		//printf("entry %x, estop %x\n", entry->keylo, estop->keylo);
		if (group->keyhi == keyhi) {
			for (; entry >= estop; entry--) { /* see note */
				//printf("entry check %x, %x\n", keylo, (entry - 1)->keylo);
				exstop = exbase + entry->limit;
				if (entry->keylo >= keylo)
					break;
				extent = exstop;
			}
		}
	}

	//printf("group %i entry %i of %i\n", gdict - 1 - group, estop + group->count - 1 - entry, group->count);
	*walk = (struct dwalk){
		.leaf = leaf,
		.group = group,
		.gstop = gstop,
		.entry = entry,
		.estop = estop,
		.exbase = exbase,
		.extent = extent,
		.exstop = exstop };
	return 0;
}

/*
 * Note!
 *
 * The dwalk probe is designed to handle not just a walk, but insert as well,
 * so it must be able to represent an entry position past the last entry of a
 * group in case an entry with a higher key than any other in the group needs
 * to be inserted.  In this case, the entry is already past the estop, so the
 * advance needs to handle that with an inequality test.  Testing for equal
 * to estop is not quite good enough.
 */

struct extent *dwalk_next(struct dwalk *walk)
{
	//printf("walk extent = %Lx, exstop = %Lx\n", (L)walk->extent->block, (L)walk->exstop->block);
	if (walk->extent >= walk->exstop) {
		//printf("next entry, entry = %x, estop = %x, \n", walk->entry->keylo, walk->estop->keylo);
		if (walk->entry-- <= walk->estop) {
			//printf("next group\n");
			if (walk->group <= walk->gstop)
				return NULL;
			walk->exbase += walk->estop->limit;
			walk->estop -= (--walk->group)->count;
		}
		walk->exstop = walk->exbase + walk->entry->limit;
	}
	return walk->extent++; // also return key
}

tuxkey_t dwalk_index(struct dwalk *walk)
{
	return (walk->group->keyhi << 24) | walk->entry->keylo;
}

#ifndef main
#define MAX_GROUP_ENTRIES 7
#else
#define MAX_GROUP_ENTRIES 255
#endif

int dwalk_pack(struct dwalk *walk, tuxkey_t index, struct extent extent)
{
	if (dwalk_index(walk) != index) {
		trace("add entry key 0x%Lx after 0x%Lx", (L)index, (L)dwalk_index(walk));
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (walk->group->keyhi != keyhi || walk->group->count >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->leaf->groups);
			/* will it fit? */
			assert(sizeof(struct entry) == sizeof(struct group));
			assert(walk->leaf->free <= walk->leaf->used - sizeof(*walk->entry));
			/* move entries down, adjust walk state */
			/* should preplan this to avoid move, need additional pack state */
			vecmove(walk->entry - 1, walk->entry, (struct entry *)walk->group - walk->entry);
			walk->leaf->used -= sizeof(struct group);
			walk->entry--;
			/* add the group */
			walk->exbase += walk->entry->limit;
			*--walk->group = (struct group){ .keyhi = keyhi };
			walk->leaf->groups++;
		}
		assert(walk->leaf->free <= walk->leaf->used - sizeof(*walk->entry));
		walk->leaf->used -= sizeof(struct entry);
		*--walk->entry = (struct entry){ .keylo = keylo, .limit = walk->extent - walk->exbase + 1 };
		walk->group->count++;
	}
	trace("add extent");
	assert(walk->leaf->free + sizeof(*walk->extent) <= walk->leaf->used);
	walk->leaf->free += sizeof(*walk->extent);
	*++walk->extent = extent;
	walk->entry->limit++;
	return 0; // extent out of order??? leaf full???
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

int dleaf_check(BTREE, struct dleaf *leaf)
{
	struct group *groups = (void *)leaf + btree->sb->blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1), *entry = entries;
	struct extent *extents = leaf->table;
	unsigned excount = 0, encount = 0;
	char *why;

	for (struct group *group = groups; group > grbase; group--) {
		entry -= group->count;
		excount += entry->limit;
		encount += group->count;
	}
	//printf("encount = %i, excount = %i, \n", encount, excount);
	why = "free count wrong";
	if (leaf->free != (void *)(extents + excount) - (void *)leaf)
		goto eek;
	why = "used count wrong";
	if (leaf->used != (void *)(entries - encount) - (void *)leaf)
		goto eek;
	return 0;
eek:
	printf("free %i, used %i\n", leaf->free, leaf->used);
	printf("%s!\n", why);
	return -1;
}

/*
 * Note that dleaf_resize, unlike other resize methods, always makes space for
 * a new entry and returns a pointer to the new entry, not the base of a group
 * of entries with the same key.  Is this a bug or a feature?  The high level
 * btree resize method does not know or care about this detail.
 */
void *dleaf_resize(BTREE, tuxkey_t key, vleaf *base, unsigned size)
{
	//key = key & 0xffffffffffffLL;
	assert(dleaf_sniff(btree, base));
	struct dleaf *leaf = base;
	struct group *groups = base + btree->sb->blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1);
	struct extent *extents = leaf->table;
	unsigned keylo = key & 0xffffff, keyhi = key >> 24;
	void *used = leaf->used + base;
	const int grouplim = MAX_GROUP_ENTRIES; /// !!! just for testing !!! ///

	/* need room for one extent + maybe one group + maybe one entry */
	if (leaf_free(btree, leaf) < sizeof(struct group) + sizeof(struct entry) + size)
		return NULL;

	/* find group position */
	struct group *group;
	for (group = groups; group > grbase; group--) {
		if (keyhi <= group->keyhi) {
			if (keyhi < group->keyhi)
				break;
			//printf("is key in this group?\n");
			if (keylo <= (entries - group->count)->keylo)
				break;
			//printf("is there another group?\n");
			if (group - 1 == grbase)
				break;
			//printf("that has the same keyhi?\n");
			if (keyhi != (group - 1)->keyhi)
				break;
		}
		entries -= group->count;
		extents += entries->limit;
	}

	/* insert new group if no match  */
	if (group == grbase || keyhi < group->keyhi || (entries - group->count)->limit == grouplim) {
		int split = group != grbase && keyhi == group->keyhi;
		printf("new group at %ti\n", group - grbase);
		memmove(used - sizeof(*group), used, (void *)(group + 1) - used);
		*group = (struct group){ .keyhi = keyhi, .count = 0 };
		used -= sizeof(*group);
		grbase--;
		entries--;
		leaf->groups++;
		if (split) {
			unsigned count = (group - 1)->count;
			(group - 1)->count -= group->count = (count + 1) / 2;
			printf("split group with count %i at %i\n", count, group->count);
			/* decrease entry limits for successor group */
			for (int i = group->count + 1; i <= count; i++)
				(entries - i)->limit -= (entries - group->count)->limit;
			if (keylo > (entries - group->count - 1)->keylo) {
				printf("insert into successor group\n");
				entries -= group->count;
				extents += entries->limit;
				group--;
			}
		}
	}

	/* find entry position */
	struct entry *enbase = --entries - group->count, *entry;
	for (entry = entries; entry > enbase; entry--)
		if (keylo <= entry->keylo)
			break;

	/* insert new entry if no match  */
	if (entry == enbase || keylo < entry->keylo) {
		printf("insert 0x%Lx at %ti in group %ti\n", (L)key, entries - entry, groups - group);
		memmove(used - sizeof(*entry), used, (void *)(entry + 1) - used);
		unsigned limit = !group->count || entry == entries ? 0 : (entry + 1)->limit;
		*entry = (struct entry){ .keylo = keylo, .limit = limit };
		used -= sizeof(*entry);
		enbase--;
		group->count++;
	}

	/* insert the extent */
	struct extent *where = extents + entry->limit;
	printf("limit = %i, free = %i\n", entry->limit, leaf_free(btree, leaf));
	int tail = base + leaf->free - (void *)where;
	assert(tail >= 0);
	memmove(where + 1, where, tail);
	leaf->free += sizeof(*where);

	/* bump entry and successor limits */
	while (entry > enbase)
		(entry--)->limit++;

	leaf->used = (void *)used - (void *)leaf;
	return where;
}

/*
 * Fast path insert
 *
 * If keyhi same as last group and keylo greater than last entry:
 *
 *  - append extent
 *  - append entry
 *  - bump last group count
 *  - increase free by 8
 *  - decrease used by 4
 */

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
	//assert(leaf_need(from) <= leaf_free(leaf));

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
	.leaf_resize = dleaf_resize,
	.leaf_chop = dleaf_chop,
	.balloc = balloc,
	.bfree = bfree,
};

#ifndef main
void dleaf_insert(BTREE, block_t key, struct dleaf *leaf, struct extent extent)
{
	printf("insert 0x%Lx -> 0x%Lx\n", (L)key, (L)extent.block);
	struct extent *store = dleaf_resize(btree, key, leaf, sizeof(extent));
	*store = extent;
}

block_t balloc(SB)
{
	return sb->nextalloc++;
}

void bfree(SB, block_t block)
{
	printf(" free %Lx\n", (L)block);
}

int dwalk_mock(struct dwalk *walk, tuxkey_t key, struct extent extent)
{
	if (dwalk_index(walk) != key) {
		trace("add entry key 0x%Lx after 0x%Lx", (L)key, (L)dwalk_index(walk));
		unsigned keylo = key & 0xffffff, keyhi = key >> 24;
		if (walk->mock_group.keyhi != keyhi || walk->mock_group.count >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->groups);
			walk->exbase += walk->mock_entry.limit;
			walk->mock_group = (struct group){ .keyhi = keyhi };
			walk->used -= sizeof(struct group);
			walk->groups++;
		}
		walk->used -= sizeof(struct entry);
		walk->mock_entry = (struct entry){ .keylo = keylo, .limit = walk->extent - walk->exbase + 1 };
		walk->mock_group.count++;
	}
	trace("add extent");
	walk->free += sizeof(*walk->extent);
	walk->extent++;
	walk->mock_entry.limit++;
	return 0;
}

int main(int argc, char *argv[])
{
	printf("--- leaf test ---\n");
	SB = &(struct sb){ .blocksize = 1 << 10 };
	struct btree *btree = &(struct btree){ .sb = sb, .ops = &dtree_ops };
	struct dleaf *leaf = leaf_create(btree);
	dleaf_chop(btree, 0x14014LL, leaf);

	unsigned hi = 1 << 24, hi2 = 3 * hi;
	unsigned keys[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, hi + 0x44, hi + 0x99 }, next = 0;
	for (int i = 1; i < 32; i++)
		dleaf_insert(btree, (i << 12) + i, leaf, (struct extent){ .block = i });
	dleaf_dump(btree, leaf);
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x111 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x222 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x333 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x444 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x555 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x666 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x777 });
	dleaf_insert(btree, keys[next++], leaf, (struct extent){ .block = 0x888 });
	dleaf_insert(btree, keys[next], leaf, (struct extent){ .block = 0x999 });
	dleaf_dump(btree, leaf);
	struct dwalk *walk = &(struct dwalk){ };
	dwalk_probe(sb, leaf, walk, 0xf00f);
//	for (struct extent *extent; (extent = dwalk_next(walk));)
//		printf("0x%Lx => 0x%Lx\n", (L)dwalk_index(walk), (L)extent->block);
	for (int i = 0; i < 2; i++) {
		dwalk_probe(sb, leaf, walk, 0x3000055);
		walk->mock_group = *walk->group;
		walk->mock_entry = *walk->entry;
		walk->groups = walk->leaf->groups;
		int (*try)(struct dwalk *walk, tuxkey_t key, struct extent extent) = i ? dwalk_pack: dwalk_mock;
		try(walk, 0x3001001, (struct extent){ .block = 0x1 });
		try(walk, 0x3001002, (struct extent){ .block = 0x1 });
		try(walk, 0x3001003, (struct extent){ .block = 0x1 });
		try(walk, 0x3001004, (struct extent){ .block = 0x1 });
		try(walk, 0x3001005, (struct extent){ .block = 0x1 });
		try(walk, 0x3001006, (struct extent){ .block = 0x1 });
		if (!i) printf("mock free = %i, used = %i\n", walk->free, walk->used);
	}
	dleaf_dump(btree, leaf);
return 0;
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
