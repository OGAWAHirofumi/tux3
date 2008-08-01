/* (c) 2008 Daniel Phillips <phillips@phunq.net>, licensed under GPL v2 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

typedef uint64_t block_t;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct extent { block_t block:48, count:6, version:10; };
struct group { u32 count:8, loghi:24; };
struct entry { u32 limit:8, loglo:24; };
struct leaf { u16 magic, free, used, groups; struct extent table[]; };

unsigned blocksize = 4096;

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
 * with the same logical address (not handled yet, which limits the number of
 * different versions in the leaf to 256).  The group count is used both to
 * know the number of entries in the group and to find the beginning of the
 * entry table for a given group, by adding up the sizes of the proceeding
 * groups.
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
 *  1) show - done
 *  2) check - started
 *  3) lookup - done
 *  4) insert - done
 *  5) split - done
 *  6) merge
 *  7) delete
 *  8) create - done
 *  9) destroy - done
 *  10) freespace
 *  11) needspace
 *  12) fuzztest
 */

struct leaf *leaf_create(void)
{
	struct leaf *leaf = malloc(blocksize);
	*leaf = (struct leaf){ .magic = 0x1eaf, .groups = 0, .free = sizeof(struct leaf), .used = blocksize };
	return leaf;
}

void leaf_destroy(struct leaf *leaf)
{
	if (leaf->magic == 0x1eaf) {
		free(leaf);
		return;
	}
	printf("bad leaf %p\n", leaf);
}

void leaf_dump(struct leaf *leaf)
{
	struct group *groups = (void *)leaf + blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1), *entry = entries;
	struct extent *extents = leaf->table;

	printf("%i entry groups:\n", leaf->groups);
	for (struct group *group = groups; group > grbase; group--) {
		printf("  %i: [%i]", groups - group, extents - leaf->table);
		struct entry *enbase = entry - group->count;
		while (entry > enbase) {
			--entry;
			unsigned offset = entry == entries - 1 ? 0 : (entry + 1)->limit;
			int count = entry->limit - offset;
			printf(" 0x%Lx ->", ((u64)group->loghi << 24) + entry->loglo);
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++)
				printf(" %Lx", (u64)(extents + offset + i)->block);
			printf(";");
		}
		printf("\n");
		entries -= group->count;
		extents += entry->limit;
	}
}

unsigned leaf_lookup(struct leaf *leaf, block_t target, unsigned *count)
{
	struct group *groups = (void *)leaf + blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1);
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;

	for (struct group *group = groups; group > grbase; group--) {
		struct entry *enbase = entries - group->count;
		if (loghi == group->loghi) {
			struct entry *entry = entries;
			while (entry > enbase)
				if ((--entry)->loglo == loglo) {
					unsigned offset = entry - enbase == group->count - 1 ? 0 : (entry + 1)->limit;
					*count = entry->limit - offset;
					return extents - leaf->table + offset;
				}
		}
		entries -= group->count;
		extents += enbase->limit;
	}
	*count = 0;
	return 0;
}

int leaf_check(struct leaf *leaf) // doesn't do any checking yet
{
	struct group *groups = (void *)leaf + blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1), *entry = entries;
	struct extent *extents = leaf->table;
	unsigned excount = 0, encount = 0;
	char *why;

	for (struct group *group = groups; group > grbase; group--) {
		excount += (entry -= group->count)->limit;
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

int leaf_insert(struct leaf *leaf, block_t target, struct extent extent)
{
	//printf("insert 0x%Lx -> 0x%Lx\n", target, (block_t)extent.block);
	struct group *groups = (void *)leaf + blocksize, *grbase = --groups - leaf->groups;
	struct entry *entries = (void *)(grbase + 1);
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;
	void *used = leaf->used + (void *)leaf;
	// need room for one extent + maybe one group + maybe one entry
	/* find group position */
	struct group *group;
	for (group = groups; group > grbase; group--) {
		if (loghi <= group->loghi)
			break;
		extents += (entries - group->count)->limit;
		entries -= group->count;
	}
	/* insert new group if no match  */
	if (group == grbase || loghi < group->loghi) {
		printf("new group at %i\n", group - grbase);
		memmove(used - sizeof(*group), used, (void *)(group + 1) - used);
		*group = (struct group){ .loghi = loghi, .count = 0 };
		used -= sizeof(*group);
		grbase--;
		entries--;
		leaf->groups++;
	}
	/* find entry position */
	struct entry *enbase = --entries - group->count, *entry;
	for (entry = entries; entry > enbase; entry--)
		if (loglo <= entry->loglo)
			break;
	/* insert new entry if no match  */
	if (entry == enbase || loglo < entry->loglo) {
		printf("insert 0x%Lx at %i in group %i\n", target, entries - entry, group - grbase);
		memmove(used - sizeof(*entry), used, (void *)(entry + 1) - used);
		*entry = (struct entry){ .loglo = loglo, .limit = !group->count ? 0 : (entry + 1)->limit };
		used -= sizeof(*entry);
		enbase--;
		group->count++;
	}
	/* insert the extent */
	struct extent *where = extents + entry->limit;
	memmove(where + 1, where, (void *)leaf + leaf->free - (void *)where);
	*where = extent;
	/* bump entry and successor limits */
	while (entry > enbase)
		(entry--)->limit++;
	/* clean up */
	leaf->used = (void *)used - (void *)leaf;
	leaf->free += sizeof(*where);
	return 0;
}

void leaf_split(struct leaf *leaf, struct leaf *dest)
{
	struct group *groups = (void *)leaf + blocksize, *grbase = groups - leaf->groups;
	struct entry *entries = (void *)grbase;
	printf("split %p into %p\n", leaf, dest);
	unsigned encount = 0, recount = 0, grsplit = 0, exsplit = 0;

	/* find middle in terms of entries (maybe unbalanced in extents) */
	for (struct group *group = groups - 1; group >= grbase; group--)
		encount += group->count;
	unsigned ensplit = encount / 2;
	for (struct group *group = groups - 1; group >= grbase; group--, grsplit++) {
		if (recount + group->count > ensplit)
			break;
		exsplit += (entries - group->count)->limit;
		entries -= group->count;
		recount += group->count;
	}

	/* may have to split a group */
	unsigned subsplit = ensplit - recount;
	if (subsplit)
		exsplit += (entries - subsplit)->limit;
	entries = (void *)grbase; /* put it back where it was */
	printf("split %i entries at group %i, entry %x\n", encount, grsplit, subsplit);
	printf("split extents at %i\n", exsplit);

	/* copy groups */
	dest->groups = leaf->groups - grsplit;
	struct group *destgroups = (void *)dest + blocksize;
	veccopy(destgroups - dest->groups, grbase, dest->groups);
	(destgroups - 1)->count -= subsplit;
	leaf->groups = grsplit + !!subsplit;
	grbase = groups - leaf->groups;
	if (subsplit)
		(groups - leaf->groups)->count = subsplit;

	/* copy entries */
	struct entry *destentries = (void *)(destgroups - dest->groups);
	unsigned encopy = encount - ensplit;
	struct entry *enbase = entries - encount;
	veccopy(destentries - encopy, enbase, encopy);
	if (subsplit)
		for (int i = 1; i <= (destgroups - 1)->count; i++)
			(destentries - i)->limit -= (enbase + encopy)->limit;
	vecmove(groups - leaf->groups - ensplit, entries - ensplit, ensplit);

	/* copy extents */
	unsigned exsize = (void *)leaf + leaf->free - (void *)(leaf->table + exsplit);
	veccopy(dest->table, leaf->table + exsplit, exsize);

	leaf->free = (void *)(leaf->table + exsplit) - (void *)leaf;
	dest->free = (void *)leaf->table + exsize - (void *)leaf;
	leaf->used = (void *)(grbase - ensplit) - (void *)leaf;
	dest->used = (void *)(groups - dest->groups - encount + ensplit) - (void *)leaf;
}


int main(int argc, char *argv[])
{
	struct leaf *leaf = leaf_create();
	printf("--- leaf test ---\n");
	unsigned hi = 1 << 24, hi2 = 2 * hi;
	unsigned targets[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, hi + 0x44, hi + 0x99 }, next = 0;
	leaf_dump(leaf);
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x111 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x222 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x333 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x444 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x555 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x666 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x777 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x888 });
	leaf_insert(leaf, targets[next], (struct extent){ .block = 0x999 });
	leaf_dump(leaf);
	for (int i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
		unsigned target = targets[i];
		unsigned count;
		unsigned found = leaf_lookup(leaf, target, &count);
		printf("lookup 0x%x, found [%i/%i]\n", target, found, count );
	}

	struct leaf *dest = leaf_create();
	leaf_split(leaf, dest);
	leaf_dump(leaf);
	leaf_dump(dest);
	leaf_check(leaf);
	leaf_check(dest);
	return 0;
}
