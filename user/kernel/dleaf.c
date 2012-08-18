/*
 * File index btree leaf operations
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

static void dleaf_btree_init(struct btree *btree)
{
	btree->entries_per_leaf = 64; /* FIXME: should depend on blocksize */
}

int dleaf_init(struct btree *btree, vleaf *leaf)
{
	*to_dleaf(leaf) = (struct dleaf){
		.magic = to_be_u16(TUX3_MAGIC_DLEAF),
		.free = to_be_u16(sizeof(struct dleaf)),
		.used = to_be_u16(btree->sb->blocksize) };
	return 0;
}

unsigned dleaf_free(struct btree *btree, vleaf *leaf)
{
	return from_be_u16(to_dleaf(leaf)->used) - from_be_u16(to_dleaf(leaf)->free);
}

static unsigned dleaf_need(struct btree *btree, vleaf *vleaf)
{
	struct dleaf *leaf = to_dleaf(vleaf);
	return btree->sb->blocksize - dleaf_free(btree, leaf) - sizeof(struct dleaf);
}

static inline tuxkey_t get_index(struct group *group, struct entry *entry)
{
	return ((tuxkey_t)group_keyhi(group) << 24) | entry_keylo(entry);
}

static int dleaf_sniff(struct btree *btree, vleaf *leaf)
{
	return to_dleaf(leaf)->magic == to_be_u16(TUX3_MAGIC_DLEAF);
}

static int dleaf_can_free(struct btree *btree, vleaf *vleaf)
{
	return dleaf_need(btree, vleaf) == 0;
}

void dleaf_dump(struct btree *btree, vleaf *vleaf)
{
	if (!tux3_trace)
		return;

	unsigned blocksize = btree->sb->blocksize;
	struct dleaf *leaf = vleaf;
	struct group *gdict = (void *)leaf + blocksize, *gbase = --gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)(gbase + 1), *entry = edict;
	struct diskextent *extents = leaf->table;

	printf("%i entry groups:\n", dleaf_groups(leaf));
	for (struct group *group = gdict; group > gbase; group--) {
		printf("  %ti/%i:", gdict - group, group_count(group));
		//printf(" [%i]", extents - leaf->table);
		struct entry *ebase = entry - group_count(group);
		while (entry > ebase) {
			--entry;
			unsigned offset = entry == edict - 1 ? 0 : entry_limit(entry + 1);
			int count = entry_limit(entry) - offset;
			printf(" %Lx =>", (L)get_index(group, entry));
			//printf(" %p (%i)", entry, entry_limit(entry));
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++) {
				struct diskextent extent = extents[offset + i];
				printf(" %Lx", (L)extent_block(extent));
				if (extent_count(extent))
					printf("/%x", extent_count(extent));
			}
			//printf(" {%u}", entry_limit(entry));
			printf(";");
		}
		printf("\n");
		extents += entry_limit(entry);
		edict -= group_count(group);
	}
}

static int dleaf_free2(struct dleaf *leaf, unsigned blocksize)
{
	struct group *gdict = (void *)leaf + blocksize, *gstop = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gstop, *entry = edict;
	struct diskextent *extents = leaf->table;

	for (struct group *group = gdict; group-- > gstop;)
		extents += entry_limit(entry -= group_count(group));
	return (void *)entry - (void *)extents;
}

static int dleaf_check(struct dleaf *leaf, unsigned blocksize)
{
	struct group *gdict = (void *)leaf + blocksize, *gstop = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gstop, *estop = edict;
	struct diskextent *extents = leaf->table;
	unsigned excount = 0, encount = 0;
	char *why;

	if (!dleaf_groups(leaf))
		return 0;

	unsigned keyhi = 0;
	struct diskextent *exbase = leaf->table;
	for (struct group *group = gdict - 1; group >= gstop; group--) {
		assert(group_keyhi(group) >= keyhi);
		assert(group_count(group) > 0);
		assert(group_count(group) <= MAX_GROUP_ENTRIES);
		keyhi = group_keyhi(group);
		struct entry *entry = estop;
		estop -= group_count(group);
		unsigned limit = 0, keylo = -1;
		while (--entry >= estop) {
			assert((int)entry_keylo(entry) > (int)keylo);
			assert(entry_limit(entry) > limit);
			keylo = entry_keylo(entry);
			limit = entry_limit(entry);
		}
		struct diskextent *exstop = exbase + entry_limit(estop);
		block_t block = 0;
		while (exbase < exstop) {
			assert(extent_block(*exbase) != block);
			exbase++;
		}
		excount += entry_limit(estop);
		encount += group_count(group);
	}
	//printf("encount = %i, excount = %i, \n", encount, excount);
	why = "used count wrong";
	if (from_be_u16(leaf->used) != (void *)(edict - encount) - (void *)leaf)
		goto eek;
	why = "free count wrong";
	if (from_be_u16(leaf->free) != (void *)(extents + excount) - (void *)leaf)
		goto eek;
	why = "free check mismatch";
	if (from_be_u16(leaf->used) - from_be_u16(leaf->free) != dleaf_free2(leaf, blocksize))
		goto eek;
	return 0;
eek:
	printf("free %i, used %i\n", from_be_u16(leaf->free), from_be_u16(leaf->used));
	printf("%s!\n", why);
	return -1;
}

static int dleaf_split_at(vleaf *from, vleaf *into, int split, unsigned blocksize)
{
	struct dleaf *leaf = from, *leaf2 = into;
	unsigned groups = dleaf_groups(leaf), groups2;
	struct group *gdict = from + blocksize, *gbase = gdict - groups;
	struct entry *edict = (void *)gbase, *ebase = (void *)leaf + from_be_u16(leaf->used);
	unsigned recount = 0, grsplit = 0, exsplit = 0;
	unsigned entries = edict - ebase;

	printf("split %p into %p at %x\n", leaf, leaf2, split);
	if (!groups)
		return 0;
	assert(split < entries);
	for (struct group *group = gdict - 1; group >= gbase; group--, grsplit++) {
		if (recount + group_count(group) > split)
			break;
		edict -= group_count(group);
		exsplit += entry_limit(edict);
		recount += group_count(group);
	}

	/* have to split a group? */
	unsigned cut = split - recount;
	if (cut)
		exsplit += entry_limit(edict - cut);
	edict = (void *)gbase; /* restore it */
	printf("split %i entries at group %i, entry %x\n", entries, grsplit, cut);
	printf("split extents at %i\n", exsplit);
	/* copy extents */
	unsigned size = from + from_be_u16(leaf->free) - (void *)(leaf->table + exsplit);
	memcpy(leaf2->table, leaf->table + exsplit, size);

	/* copy groups */
	struct group *gdict2 = (void *)leaf2 + blocksize;
	set_dleaf_groups(leaf2, groups2 = (groups - grsplit));
	veccopy(gdict2 - dleaf_groups(leaf2), gbase, dleaf_groups(leaf2));
	inc_group_count(gdict2 - 1, -cut);
	set_dleaf_groups(leaf, groups = (grsplit + !!cut));
	gbase = gdict - groups;
	if (cut)
		set_group_count(gdict - groups, cut);

	/* copy entries */
	struct entry *edict2 = (void *)(gdict2 - groups2);

	assert((struct entry *)((void *)leaf + from_be_u16(leaf->used)) == edict - entries);

	unsigned encopy = entries - split;
	veccopy(edict2 - encopy, ebase, encopy);
	if (cut)
		for (int i = 1; i <= group_count((gdict2 - 1)); i++)
			inc_entry_limit(edict2 - i, -entry_limit(edict - split));
	vecmove(gdict - groups - split, edict - split, split);

	/* clean up */
	leaf->free = to_be_u16((void *)(leaf->table + exsplit) - from);
	leaf->used = to_be_u16((void *)(gbase - split) - from);
	leaf2->free = to_be_u16((void *)leaf->table + size - from);
	leaf2->used = to_be_u16((void *)(gdict - groups2 - encopy) - from);
	memset(from + from_be_u16(leaf->free), 0, from_be_u16(leaf->used) - from_be_u16(leaf->free));
	assert(!dleaf_check(leaf, blocksize));
	assert(!dleaf_check(leaf2, blocksize));
	return groups2;
}

/*
 * Split dleaf at middle in terms of entries, may be unbalanced in extents.
 * Not used for now because we do the splits by hand in filemap.c
 */
static tuxkey_t dleaf_split(struct btree *btree, tuxkey_t hint, vleaf *from, vleaf *into)
{
	struct dleaf *leaf = to_dleaf(from), *leaf2 = to_dleaf(into);
	assert(dleaf_sniff(btree, from));
	unsigned blocksize = btree->sb->blocksize;
	struct group *gdict = from + blocksize, *gbase = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gbase;
	struct entry *ebase = (void *)leaf + from_be_u16(leaf->used);
	unsigned entries = edict - ebase;
	assert(entries >= 2);
	unsigned groups2 = dleaf_split_at(from, into, entries / 2, blocksize);
	struct group *gdict2 = (void *)leaf2 + blocksize;

	return get_index(gdict2 - 1, (struct entry *)(gdict2 - groups2) - 1);
}

/*
 * Try to merge dleaf
 *
 * return value:
 * 0 - couldn't merge
 * 1 - merged
 */
int dleaf_merge(struct btree *btree, vleaf *vinto, vleaf *vfrom)
{
	struct dleaf *leaf = to_dleaf(vinto), *from = to_dleaf(vfrom);
	struct group *gdict = (void *)leaf + btree->sb->blocksize;
	struct group *gstop = gdict - dleaf_groups(leaf);
	struct entry *edict = (struct entry *)gstop;
	unsigned free = from_be_u16(leaf->free);
	struct group *gdict2 = (void *)from + btree->sb->blocksize;
	struct group *group2 = gdict2 - 1;
	struct group *gstop2 = gdict2 - dleaf_groups(from);
	struct entry *edict2 = (struct entry *)gstop2;
	unsigned merge_gcount = 0, rest_gcount = 0;
	int can_merge_group = 0;

	/* Source is empty, so we do nothing */
	if (dleaf_groups(from) == 0)
		return 1;

	/* Destination is empty, so we just copy */
	if (dleaf_groups(leaf) == 0) {
		unsigned used = from_be_u16(from->used);
		memcpy(leaf, from, from_be_u16(from->free));
		memcpy((void *)leaf + used, (void *)from + used, btree->sb->blocksize - used);
		return 1;
	}

	/*
	 * Check if there is space.
	 * FIXME: we may be able to merge more if group/entry can be merged
	 */
	if (dleaf_need(btree, vfrom) > dleaf_free(btree, vinto))
		return 0;

	/* Try to merge group, and prepare to adjust */
	if (group_keyhi(gstop) == group_keyhi(group2) &&
	    group_count(gstop) < MAX_GROUP_ENTRIES) {
		unsigned gcount2 = group_count(group2);
		unsigned room = MAX_GROUP_ENTRIES - group_count(gstop);
		/* All entries can merge to this group? */
		if (room < gcount2) {
			/* Calc adjust for the rest of group/entries */
			rest_gcount = gcount2 - room;
			gcount2 = room;
		} else
			can_merge_group = 1;

		/* group/entries which merge */
		merge_gcount = gcount2;
	}

	/* append extents */
	unsigned size = from_be_u16(from->free) - sizeof(struct dleaf);
	memcpy((void *)leaf + free, from->table, size);
	leaf->free = to_be_u16(free + size);

	/* make space and append groups except for possibly merged group */
	assert(sizeof(struct group) == sizeof(struct entry));
	unsigned addgroups = dleaf_groups(from) - can_merge_group;
	struct entry *ebase2 = (void *)from + from_be_u16(from->used);
	struct entry *ebase = (void *)leaf + from_be_u16(leaf->used);
	vecmove(ebase - addgroups, ebase, edict - ebase);
	veccopy(gstop - addgroups, gstop2, addgroups);
	ebase -= addgroups;
	inc_dleaf_groups(leaf, addgroups);

	/* append entries */
	size = (void *)edict2 - (void *)ebase2;
	memcpy((void *)ebase - size, ebase2, size);
	leaf->used = to_be_u16((void *)ebase - size - (void *)leaf);

	if (merge_gcount) {
		/* adjust merged group */
		struct entry *estop = ebase - merge_gcount;
		unsigned limit_adjust = entry_limit(ebase);
		inc_group_count(gstop, merge_gcount);
		while (--ebase >= estop)
			inc_entry_limit(ebase, limit_adjust);
		if (rest_gcount) {
			/* adjust the group/entries which couldn't merge */
			ebase = estop;
			estop = ebase - rest_gcount;
			limit_adjust = entry_limit(edict2 - merge_gcount);
			set_group_count(gstop - 1, rest_gcount);
			while (--ebase >= estop)
				inc_entry_limit(ebase, -limit_adjust);
		}
	}
	assert(!dleaf_check(leaf, btree->sb->blocksize));

	return 1;
}

/*
 * dleaf format and dwalk structure
 *
 *         min address +--------------------------+
 *                     |     dleaf header         |
 *                   | | extent <0> (gr 0, ent 0) | __ walk->exbase
 * growing downwards | | extent <0> (gr 1, ent 0) | __ walk->extent
 *                   | | extent <1> (gr 1, ent 1) | __ walk->exstop
 *                   V | extent <2> (gr 1, ent 2) |
 *                     |                          |
 *                     |        .......           |
 *                     |                          | __ walk->estop
 *                     | entry <2> (gr 1)         |
 *                     | entry <1> (gr 1)         | __ walk->entry
 *                   ^ | entry <0> (gr 1)         |
 *                   | | entry <0> (gr 0)         | __ walk->group,walk->gstop
 * growing upwards   | | group <1>                |
 *                   | | group <0>                |
 *         max address +--------------------------+ __ walk->gdict
 *
 * The above is dleaf format, and now dwalk_next() was called 2 times.
 *
 *      ->gdict is the end of dleaf.
 *      ->group is the current group (group <1>)
 *      ->gstop is the last group in this dleaf
 *      ->entry is the current entry (entry <0> (gr 1))
 *      ->estop is the last entry in current group
 *      ->exbase is the first extent in current group
 *      ->extent is the current extent (extent <1> (gr1, ent 1)).
 *      ->exstop is the first extent in next entry.
 *        (I.e. the address that dwalk_next() has to update to next entry.
 *        If there is no next, it will stop with ->extent == ->exstop.)
 */

void dwalk_redirect(struct dwalk *walk, struct dleaf *src, struct dleaf *dst)
{
#ifndef ATOMIC
	return;
#endif
	walk->leaf = dst;
	walk->group = ptr_redirect(walk->group, src, dst);
	walk->gstop = ptr_redirect(walk->gstop, src, dst);
	walk->gdict = ptr_redirect(walk->gdict, src, dst);
	walk->entry = ptr_redirect(walk->entry, src, dst);
	walk->estop = ptr_redirect(walk->estop, src, dst);
	walk->exbase = ptr_redirect(walk->exbase, src, dst);
	walk->extent = ptr_redirect(walk->extent, src, dst);
	walk->exstop = ptr_redirect(walk->exstop, src, dst);
}

/* FIXME: current code is assuming the entry has only one extent. */

/* The first extent in dleaf */
static int dwalk_first(struct dwalk *walk)
{
	return walk->leaf->table == walk->extent;
}

/* The end of extent in dleaf */
int dwalk_end(struct dwalk *walk)
{
	return walk->extent == walk->exstop;
}

tuxkey_t dwalk_index(struct dwalk *walk)
{
	return get_index(walk->group, walk->entry);
}

block_t dwalk_block(struct dwalk *walk)
{
	return extent_block(*walk->extent);
}

unsigned dwalk_count(struct dwalk *walk)
{
	return extent_count(*walk->extent);
}

/* unused */
void dwalk_dump(struct dwalk *walk)
{
	if (walk->leaf->table == walk->exstop) {
		trace_on("empty leaf");
		return;
	}
	if (dwalk_end(walk)) {
		trace_on("end of extent");
		return;
	}
	struct diskextent *entry_exbase;
	if (walk->entry + 1 == walk->estop + group_count(walk->group))
		entry_exbase = walk->exbase;
	else
		entry_exbase = walk->exbase + entry_limit(walk->entry + 1);
	trace_on("leaf %p", walk->leaf);
	trace_on("group %tu/%tu", (walk->gdict - walk->group) - 1, walk->gdict - walk->gstop);
	trace_on("entry %tu/%u", group_count(walk->group) - (walk->entry - walk->estop) - 1, group_count(walk->group));
	trace_on("extent %tu/%tu", walk->extent - entry_exbase, walk->exstop - entry_exbase);
}

static void dwalk_check(struct dwalk *walk)
{
	if (!dleaf_groups(walk->leaf)) {
		assert(walk->group == walk->gstop);
		assert(walk->entry == walk->estop);
		assert(walk->exbase == walk->extent);
		assert(walk->extent == walk->exstop);
		assert(walk->leaf->table == walk->exstop);
	} else if (dwalk_end(walk)) {
		assert(walk->group == walk->gstop);
		assert(walk->entry == walk->estop);
		assert(walk->exbase < walk->extent);
		assert(walk->extent == walk->exstop);
	} else {
		assert(walk->group >= walk->gstop);
		assert(walk->entry >= walk->estop);
		assert(walk->exbase <= walk->extent);
		assert(walk->extent < walk->exstop);
		/*
		 * This checks ->entry has only 1 ->extent.
		 * FIXME (and re-think): Assuming dleaf->entry has only 1
		 * ->extent on some functions
		 */
		if (walk->entry + 1 == walk->estop + group_count(walk->group))
			assert(entry_limit(walk->entry) == 1);
		else
			assert(entry_limit(walk->entry) - entry_limit(walk->entry + 1) == 1);
	}
}

/* Set the cursor to next extent */
int dwalk_next(struct dwalk *walk)
{
	/* last extent of this dleaf, or empty dleaf */
	if (dwalk_end(walk))
		return 0;
	walk->extent++;
	if (walk->extent == walk->exstop) {
		if (walk->entry == walk->estop) {
			if (walk->group == walk->gstop)
				return 0;
			walk->group--;
			walk->exbase += entry_limit(walk->estop);
			walk->estop -= group_count(walk->group);
		}
		walk->entry--;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	dwalk_check(walk);
	return 1;
}

/* Back to the previous extent. (i.e. rewind the previous dwalk_next()) */
int dwalk_back(struct dwalk *walk)
{
	/* first extent of this dleaf, or empty dleaf */
	if (dwalk_first(walk))
		return 0;
	struct diskextent *entry_exbase;

	if (walk->entry + 1 == walk->estop + group_count(walk->group))
		entry_exbase = walk->exbase;
	else
		entry_exbase = walk->exbase + entry_limit(walk->entry + 1);
	walk->extent--;
	if (walk->extent < entry_exbase) {
		if (walk->extent < walk->exbase) {
			if (walk->group == walk->gdict)
				return 1;
			walk->group++;
			walk->estop = walk->entry + 1;
			walk->exbase -= entry_limit(walk->entry + 1);
		}
		walk->entry++;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	dwalk_check(walk);
	return 1;
}

/*
 * Probe the extent position with key. If not found, position is next
 * extent of key.  If probed all extents return 0, otherwise return 1
 * (I.e. current extent is valid. IOW, !dwalk_end()).
 */
int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key)
{
	trace("probe for 0x%Lx", (L)key);
	unsigned keylo = key & 0xffffff, keyhi = key >> 24;

	walk->leaf = leaf;
	walk->gdict = (void *)leaf + blocksize;
	walk->gstop = walk->gdict - dleaf_groups(leaf);
	walk->group = walk->gdict;
	walk->estop = (struct entry *)walk->gstop;
	walk->exbase = leaf->table;
	if (!dleaf_groups(leaf)) {
		/* dwalk_first() and dwalk_end() will return true */
		walk->entry = (struct entry *)walk->gstop;
		walk->extent = leaf->table;
		walk->exstop = leaf->table;
		dwalk_check(walk);
		return 0;
	}

	while (walk->group > walk->gstop) {
		walk->group--;
		walk->entry = walk->estop - 1;
		walk->estop -= group_count(walk->group);
		if (group_keyhi(walk->group) > keyhi)
			goto no_group;
		if (group_keyhi(walk->group) == keyhi) {
			if (entry_keylo(walk->entry) > keylo)
				goto no_group;
			if (walk->group == walk->gstop)
				goto probe_entry;
			if (group_keyhi(walk->group - 1) > keyhi)
				goto probe_entry;
			if (entry_keylo(walk->estop - 1) > keylo)
				goto probe_entry;
		}
		walk->exbase += entry_limit(walk->estop);
	}
	/* There is no group after this key */
	walk->entry = walk->estop;
	walk->exstop = walk->exbase;
	walk->extent = walk->exbase;
	walk->exbase = walk->exbase - entry_limit(walk->estop);
	dwalk_check(walk);
	return 0;

no_group:
	/* There is no interesting group, set first extent in this group */
	walk->extent = walk->exbase;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	dwalk_check(walk);
	return 1;

probe_entry:
	/* There is interesting group, next is probe interesting entry */
	walk->extent = walk->exbase;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	while (walk->entry > walk->estop) {
		if (entry_keylo(walk->entry - 1) > keylo)
			break;
		walk->entry--;
		walk->extent = walk->exstop;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	/* Now, entry has the nearest keylo (<= key), probe extent */
	/* FIXME: this is assuming the entry has only one extent */
	if (key < dwalk_index(walk) + dwalk_count(walk))
		return 1;
	/* This entry didn't have the target extent, set next entry */
	dwalk_next(walk);
	return !dwalk_end(walk);
}

int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct diskextent extent)
{
	if (!dleaf_groups(walk->leaf) || walk->entry == walk->estop || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!walk->mock.groups || group_keyhi(&walk->mock.group) != keyhi || group_count(&walk->mock.group) >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->mock.groups);
			walk->exbase += entry_limit(&walk->mock.entry);
			walk->mock.group = make_group(keyhi, 0);
			walk->mock.used -= sizeof(struct group);
			walk->mock.groups++;
		}
		walk->mock.used -= sizeof(struct entry);
		walk->mock.entry = make_entry(keylo, walk->extent - walk->exbase);
		inc_group_count(&walk->mock.group, 1);
	}
	trace("add extent 0x%Lx => 0x%Lx/%x", (L)index, (L)extent_block(extent), extent_count(extent));
	walk->mock.free += sizeof(*walk->extent);
	walk->extent++;
	inc_entry_limit(&walk->mock.entry, 1);
	return 0;
}

/* This copy extents >= this extent to another dleaf. */
void dwalk_copy(struct dwalk *walk, struct dleaf *dest)
{
	struct dleaf *leaf = walk->leaf;
	unsigned blocksize = (void *)walk->gdict - (void *)leaf;

	assert(dleaf_groups(dest) == 0);
	if (dwalk_end(walk))
		return;
	if (dwalk_first(walk)) {
		memcpy(dest, leaf, blocksize);
		return;
	}

	struct group *gdict2 = (void *)dest + blocksize;
	unsigned groups2 = walk->group + 1 - walk->gstop;
	struct entry *ebase = (void *)leaf + from_be_u16(leaf->used);
	unsigned entries = (walk->entry + 1) - ebase;
	struct entry *edict2 = (struct entry *)(gdict2 - groups2);
	struct diskextent *exend = (void *)leaf + from_be_u16(leaf->free);
	struct diskextent *entry_exbase;
	unsigned limit_adjust, extents;

	if (walk->entry + 1 == walk->estop + group_count(walk->group)) {
		entry_exbase = walk->exbase;
		limit_adjust = 0;
	} else {
		entry_exbase = walk->exbase + entry_limit(walk->entry + 1);
		limit_adjust = entry_limit(walk->entry + 1);
	}
	extents = exend - entry_exbase;

	veccopy(gdict2 - groups2, walk->gstop, groups2);
	veccopy(edict2 - entries, ebase, entries);
	veccopy(dest->table, entry_exbase, extents);

	unsigned gcount2 = (walk->entry + 1) - walk->estop;
	set_dleaf_groups(dest, groups2);
	dest->free = to_be_u16((void *)(dest->table + extents) - (void *)dest);
	dest->used = to_be_u16((void *)(edict2 - entries) - (void *)dest);
	set_group_count(gdict2 - 1, gcount2);
	struct entry *entry2 = edict2 - 1, *estop2 = edict2 - gcount2;
	while (entry2 >= estop2) {
		inc_entry_limit(entry2, -limit_adjust);
		entry2--;
	}
	assert(!dleaf_check(dest, blocksize));
}

/* This removes extents >= this extent. (cursor position is dwalk_end()). */
void dwalk_chop(struct dwalk *walk)
{
	trace(" ");
	if (dwalk_end(walk))
		return;
	struct dleaf *leaf = walk->leaf;

	if (dwalk_first(walk)) {
		unsigned blocksize = (void *)walk->gdict - (void *)leaf;
		set_dleaf_groups(leaf, 0);
		leaf->free = to_be_u16(sizeof(struct dleaf));
		leaf->used = to_be_u16(blocksize);
		/* Initialize dwalk state */
		dwalk_probe(leaf, blocksize, walk, 0);
		return;
	}

	/* If extent is first extent on this group, remove this group too */
	dwalk_back(walk);

	struct entry *ebase = walk->estop + group_count(walk->group);
	void *entry = walk->entry;
	set_dleaf_groups(leaf, walk->gdict - walk->group);
	set_group_count(walk->group, ebase - walk->entry);
	entry += (void *)walk->group - (void *)walk->gstop;
	memmove(entry, walk->entry, (void *)walk->gstop - (void *)walk->entry);
	walk->estop = walk->entry = entry;
	walk->gstop = walk->group;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	walk->extent = walk->exstop;
	leaf->free = to_be_u16((void *)walk->exstop - (void *)leaf);
	leaf->used = to_be_u16((void *)walk->estop - (void *)leaf);
	dwalk_check(walk);
	assert(!dleaf_check(leaf, (void *)walk->gdict - (void *)leaf));
}

/*
 * Add extent to dleaf. This can use only if dwalk_end() is true.
 * Note, dwalk state is invalid after this.  (I.e. it can be used only
 * for dwalk_add())
 */
int dwalk_add(struct dwalk *walk, tuxkey_t index, struct diskextent extent)
{
	struct dleaf *leaf = walk->leaf;
	unsigned groups = dleaf_groups(leaf);
	unsigned free = from_be_u16(leaf->free);
	unsigned used = from_be_u16(leaf->used);

	/* FIXME: assume entry has only one extent */
	assert(!groups || dwalk_index(walk) != index);
	assert(extent_block(extent) > 0 && extent_count(extent) > 0);

	trace("group %ti/%i", walk->gstop + groups - 1 - walk->group, groups);
	if (!groups || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!groups || group_keyhi(walk->group) != keyhi || group_count(walk->group) >= MAX_GROUP_ENTRIES) {
			trace("add group %i", groups);
			/* will it fit? */
			assert(sizeof(*walk->entry) == sizeof(*walk->group));
			assert(free <= used - sizeof(*walk->entry));
			/* move entries down, adjust walk state */
			/* could preplan this to avoid move: need additional pack state */
			vecmove(walk->entry - 1, walk->entry, (struct entry *)walk->group - walk->entry);
			walk->entry--; /* adjust to moved position */
			walk->exbase += groups ? entry_limit(walk->entry) : 0;
			*--walk->group = make_group(keyhi, 0);
			used -= sizeof(*walk->group);
			set_dleaf_groups(leaf, ++groups);
		}
		assert(free <= used - sizeof(*walk->entry));
		used -= sizeof(*walk->entry);
		leaf->used = to_be_u16(used);
		*--walk->entry = make_entry(keylo, walk->extent - walk->exbase);
		inc_group_count(walk->group, 1);
	}
	trace("add extent %ti", walk->extent - leaf->table);
	assert(free + sizeof(*walk->extent) <= used);
	free += sizeof(*walk->extent);
	leaf->free = to_be_u16(free);
	*walk->extent++ = extent;
	inc_entry_limit(walk->entry, 1);

	assert(!dleaf_check(leaf, (void *)walk->gdict - (void *)walk->leaf));

	return 0; // extent out of order??? leaf full???
}

/* Update this extent. The caller have to check new extent isn't overlapping. */
static void dwalk_update(struct dwalk *walk, struct diskextent extent)
{
	*walk->extent = extent;
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
static int dleaf_chop(struct btree *btree, tuxkey_t start, u64 len,vleaf *vleaf)
{
	struct sb *sb = btree->sb;
	struct dleaf *leaf = to_dleaf(vleaf);
	struct dwalk walk;

	/* FIXME: range chop is unsupported for now */
	assert(len == TUXKEY_LIMIT);

	if (!dwalk_probe(leaf, sb->blocksize, &walk, start))
		return 0;

	/* Chop this extent partially */
	if (dwalk_index(&walk) < start) {
		block_t block = dwalk_block(&walk);
		unsigned count = start - dwalk_index(&walk);

		defer_bfree(&sb->defree, block + count, dwalk_count(&walk) - count);
		log_bfree(sb, block + count, dwalk_count(&walk) - count);

		dwalk_update(&walk, make_extent(block, count));
		if (!dwalk_next(&walk))
			goto out;
	}
	struct dwalk rewind = walk;
	do {
		defer_bfree(&sb->defree, dwalk_block(&walk), dwalk_count(&walk));
		log_bfree(sb, dwalk_block(&walk), dwalk_count(&walk));
	} while (dwalk_next(&walk));
	dwalk_chop(&rewind);
out:
	assert(!dleaf_check(leaf, sb->blocksize));
	return 1;
}

struct btree_ops dtree1_ops = {
	.btree_init	= dleaf_btree_init,
	.leaf_init	= dleaf_init,
	.leaf_split	= dleaf_split,
//	.leaf_resize	= dleaf_resize,
	.leaf_chop	= dleaf_chop,
	.leaf_merge	= dleaf_merge,
	.balloc		= balloc,
	.bfree		= bfree,

	.leaf_sniff	= dleaf_sniff,
	.leaf_can_free	= dleaf_can_free,
	.leaf_dump	= dleaf_dump,
};
