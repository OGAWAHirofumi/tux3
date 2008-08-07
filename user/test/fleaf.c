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
#include "tux3.h"

struct extent { block_t block:48, count:6, version:10; };
struct group { u32 count:8, loghi:24; };
struct entry { u32 limit:8, loglo:24; };
struct fleaf { u16 magic, free, used, groups; struct extent table[]; };

typedef u64 tuxkey_t;

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

/*
 * file index leaf operations:
 *
 *  1) dump - done
 *  2) check - started
 *  3) lookup - done
 *  4) insert - done
 *  5) split - done
 *  6) merge - done
 *  7) delete - thinking about it
 *  8) create - done
 *  9) destroy - done
 *  10) freespace - done
 *  11) needspace - done
 *  12) fuzztest - started
 */

int leaf_init(SB, struct fleaf *leaf)
{
	if (!leaf)
		return -1;
	*leaf = (struct fleaf){ .magic = 0x1eaf, .free = sizeof(struct fleaf), .used = sb->blocksize };
	return 0;
}

struct fleaf *leaf_create(SB)
{
	struct fleaf *leaf = malloc(sb->blocksize);
	leaf_init(sb, leaf);
	return leaf;
}

void leaf_destroy(SB, struct fleaf *leaf)
{
	assert(leaf->magic == 0x1eaf);
	free(leaf);
}

unsigned leaf_free(SB, struct fleaf *leaf)
{
	return leaf->used - leaf->free;
}

unsigned leaf_used(SB, struct fleaf *leaf)
{
	return sb->blocksize - leaf_free(sb, leaf) - sizeof(struct fleaf);
}

void leaf_dump(SB, struct fleaf *leaf)
{
	struct group *groups = (void *)leaf + sb->blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1), *entry = entries;
	struct extent *extents = leaf->table;

	printf("%i entry groups:\n", leaf->groups);
	for (struct group *group = groups; group > grbase; group--) {
		printf("  %u/%i:", groups - group, group->count);
		//printf(" [%i]", extents - leaf->table);
		struct entry *enbase = entry - group->count;
		while (entry > enbase) {
			--entry;
			unsigned offset = entry == entries - 1 ? 0 : (entry + 1)->limit;
			int count = entry->limit - offset;
			printf(" %Lx ->", ((u64)group->loghi << 24) + entry->loglo);
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++)
				printf(" %Lx", (u64)(extents + offset + i)->block);
			//printf(" {%u}", entry->limit);
			printf(";");
		}
		printf("\n");
		entries -= group->count;
		extents += entry->limit;
	}
}

void *leaf_lookup(SB, struct fleaf *leaf, block_t target, unsigned *count)
{
	struct group *groups = (void *)leaf + sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;

	for (struct group *group = groups - 1; group >= grbase; group--) {
		struct entry *enbase = entries - group->count;
		if (loghi == group->loghi) {
			for (struct entry *entry = entries; entry > enbase;)
				if ((--entry)->loglo == loglo) {
					unsigned offset = entry - enbase == group->count - 1 ? 0 : (entry + 1)->limit;
					*count = entry->limit - offset;
					return extents + offset;
				}
		}
		/* can fail out early here */
		entries -= group->count;
		extents += enbase->limit;
	}
	*count = 0;
	return NULL;
}

int leaf_check(SB, struct fleaf *leaf)
{
	struct group *groups = (void *)leaf + sb->blocksize, *grbase = --groups - leaf->groups;
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

int leaf_insert(SB, struct fleaf *leaf, block_t target, struct extent extent)
{
target = target & 0xffffffffffffLL;
	printf("insert 0x%Lx -> 0x%Lx\n", target, (block_t)extent.block);
	struct group *groups = (void *)leaf + sb->blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1);
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;
	void *used = leaf->used + (void *)leaf;
	const int grouplim = 7;

	/* need room for one extent + maybe one group + maybe one entry */
	if (sb, leaf_free(sb, leaf) < sizeof(struct group) + sizeof(struct entry) +  sizeof(struct extent))
		return 1;

	/* find group position */
	struct group *group;
	for (group = groups; group > grbase; group--) {
		if (loghi <= group->loghi) {
			if (loghi < group->loghi)
				break;
			//printf("is target in this group?\n");
			if (loglo <= (entries - group->count)->loglo)
				break;
			//printf("is there another group?\n");
			if (group - 1 == grbase)
				break;
			//printf("that has the same loghi?\n");
			if (loghi != (group - 1)->loghi)
				break;
		}
		entries -= group->count;
		extents += entries->limit;
	}

	/* insert new group if no match  */
	if (group == grbase || loghi < group->loghi || (entries - group->count)->limit == grouplim) {
		int split = group != grbase && loghi == group->loghi;
		printf("new group at %u\n", group - grbase);
		memmove(used - sizeof(*group), used, (void *)(group + 1) - used);
		*group = (struct group){ .loghi = loghi, .count = 0 };
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
			if (loglo > (entries - group->count - 1)->loglo) {
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
		if (loglo <= entry->loglo)
			break;

	/* insert new entry if no match  */
	if (entry == enbase || loglo < entry->loglo) {
		printf("insert 0x%Lx at %u in group %u\n", target, entries - entry, groups - group);
		memmove(used - sizeof(*entry), used, (void *)(entry + 1) - used);
		*entry = (struct entry){ .loglo = loglo, .limit = !group->count ? 0 : (entry + 1)->limit };
		used -= sizeof(*entry);
		enbase--;
		group->count++;
	}

	/* insert the extent */
	struct extent *where = extents + entry->limit;
	printf("limit = %i, free = %i\n", entry->limit, leaf_free(sb, leaf));
	int tail = (void *)leaf + leaf->free - (void *)where;
	assert(tail >= 0);
	memmove(where + 1, where, tail);
	leaf->free += sizeof(*where);
	*where = extent;

	/* bump entry and successor limits */
	while (entry > enbase)
		(entry--)->limit++;

	leaf->used = (void *)used - (void *)leaf;
	return 0;
}

/*
 * Fast path insert
 *
 * If loghi same as last group and loglo greater than last entry:
 *
 *  - append extent
 *  - append entry
 *  - bump last group count
 *  - increase free by 8
 *  - decrease used by 4
 */

tuxkey_t leaf_split(SB, struct fleaf *leaf, struct fleaf *dest, int fudge)
{
	void *const base = (void *)leaf;
	struct group *groups = base + sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	printf("split %p into %p\n", leaf, dest);
	unsigned encount = 0, recount = 0, grsplit = 0, exsplit = 0;

	/* find middle in terms of entries - may be unbalanced in extents */
	for (struct group *group = groups - 1; group >= grbase; group--)
		encount += group->count;
	unsigned split = encount / 2 + /* test!!! */fudge;
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
	unsigned size = base + leaf->free - (void *)(leaf->table + exsplit);
	memcpy(dest->table, leaf->table + exsplit, size);

	/* copy groups */
	struct group *destgroups = (void *)dest + sb->blocksize;
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
	leaf->free = (void *)(leaf->table + exsplit) - base;
	dest->free = (void *)leaf->table + size - base;
	leaf->used = (void *)(grbase - split) - base;
	dest->used = (void *)(groups - dest->groups - encount + split) - base;
	memset(base + leaf->free, 0, leaf->used - leaf->free);
	return ((destgroups - 1)->loghi << 24) | (destentries - 1)->loglo;
}

void leaf_merge(SB, struct fleaf *leaf, struct fleaf *from)
{
	struct group *groups = (void *)leaf + sb->blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	printf("merge %p into %p\n", from, leaf);
	//assert(leaf_used(from) <= leaf_free(leaf));

	/* append extents */
	unsigned size = from->free - sizeof(struct fleaf);
	memcpy((void *)leaf + leaf->free, from->table, size);
	leaf->free += size;

	/* merge last group (lowest) with first of from (highest)? */
	struct group *fromgroups = (void *)from + sb->blocksize;
	int uncut = leaf->groups && from->groups && ((fromgroups - 1)->loghi == grbase->loghi);

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

void fleaftest(SB)
{
	printf("--- leaf test ---\n");
	struct fleaf *leaf = leaf_create(sb);

	unsigned hi = 1 << 24, hi2 = 3 * hi;
	unsigned targets[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, hi + 0x44, hi + 0x99 }, next = 0;
	for (int i = 0; i < 28; i++)
{
		leaf_insert(sb, leaf, i << 12 + i, (struct extent){ .block = i });
//		leaf_insert(sb, leaf, (i << 12) + i, (struct extent){ .block = i });
	leaf_dump(sb, leaf);
}
return;
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x111 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x222 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x333 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x444 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x555 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x666 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x777 });
	leaf_insert(sb, leaf, targets[next++], (struct extent){ .block = 0x888 });
	leaf_insert(sb, leaf, targets[next], (struct extent){ .block = 0x999 });
	leaf_dump(sb, leaf);
	for (int i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
		unsigned target = targets[i];
		unsigned count;
		void *found = leaf_lookup(sb, leaf, target, &count);
		if (count) {
			printf("lookup 0x%x, found [%i] ", target, count );
			hexdump(found, count);
		} else
			printf("0x%x not found\n", target);
	}

	struct fleaf *dest = leaf_create(sb);
	tuxkey_t key = leaf_split(sb, leaf, dest, 0);
	printf("split key 0x%Lx\n", key);
	leaf_dump(sb, leaf);
	leaf_dump(sb, dest);
	leaf_check(sb, leaf);
	leaf_check(sb, dest);
	leaf_merge(sb, leaf, dest);
	leaf_check(sb, leaf);
	leaf_dump(sb, leaf);
	leaf_destroy(sb, leaf);
	leaf_destroy(sb, dest);
}

int main(int argc, char *argv[])
{
	fleaftest(&(struct sb){ .blocksize = 4096 });
	return 0;
}
