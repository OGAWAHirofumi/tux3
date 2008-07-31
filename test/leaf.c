/* (c) 2008 Daniel Phillips <phillips@phunq.net>, licensed under GPL v2 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

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
 * A leaf has a small header, immediately followed by a table of extents.  A
 * two level index grows down from the top of the leaf towards the top of the
 * extent table.  The index maps each unique logical address in the leaf to one
 * or more extents beginning at that address.
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
 *  5) split - started
 *  6) merge
 *  7) delete
 *  8) fuzz
 */

void leaf_dump(struct leaf *leaf)
{
	struct group *groups = (void *)leaf + blocksize, *end1 = --groups - leaf->groups;
	struct entry *entries = (void *)(end1 + 1), *entry = entries;
	struct extent *extents = leaf->table;

	printf("%i entry groups:\n", leaf->groups);
	for (struct group *group = groups; group > end1; group--) {
		printf("  %i: [%i]", group - end1, extents - leaf->table);
		struct entry *end2 = entry - group->count;
		while (entry > end2) {
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
	struct group *groups = (void *)leaf + blocksize, *end1 = --groups - leaf->groups;
	struct entry *entries = (void *)(end1 + 1);
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;

	for (struct group *group = groups; group > end1; group--) {
		struct entry *end2 = entries - group->count;
		if (loghi == group->loghi) {
			struct entry *entry = entries;
			while (entry > end2)
				if ((--entry)->loglo == loglo) {
					unsigned offset = entry - end2 == group->count - 1 ? 0 : (entry + 1)->limit;
					*count = entry->limit - offset;
					return extents - leaf->table + offset;
				}
		}
		entries -= group->count;
		extents += end2->limit;
	}
	*count = 0;
	return 0;
}

void leaf_check(struct leaf *leaf) // doesn't do any checking yet
{
	struct group *groups = (void *)leaf + blocksize, *end1 = --groups - leaf->groups;
	struct entry *entries = (void *)(end1 + 1), *entry = entries;
	struct extent *extents = leaf->table;
	unsigned excount = 0, encount = 0;

	for (struct group *group = groups; group > end1; group--) {
		excount += (entry -= group->count)->limit;
		encount += group->count;
	}
	//printf("encount = %i, excount = %i, \n", encount, excount);
	leaf->free = (void *)(extents + excount) - (void *)leaf;
	leaf->used = (void *)(entries - encount) - (void *)leaf;
	//printf("free %i, used %i\n", leaf->free, leaf->used);
}

int leaf_insert(struct leaf *leaf, block_t target, struct extent extent)
{
	//printf("insert 0x%Lx -> 0x%Lx\n", target, (block_t)extent.block);
	struct group *groups = (void *)leaf + blocksize, *end1 = --groups - leaf->groups;
	struct entry *entries = (void *)(end1 + 1);
	struct extent *extents = leaf->table;
	unsigned loglo = target & 0xffffff, loghi = target >> 24;
	void *used = leaf->used + (void *)leaf;
	// need room for one extent + maybe one group + maybe one entry
	/* find group position */
	struct group *group;
	for (group = groups; group > end1; group--) {
		if (loghi <= group->loghi)
			break;
		extents += (entries - group->count)->limit;
		entries -= group->count;
	}
	/* insert new group if no match  */
	if (group == end1 || loghi < group->loghi) {
		printf("new group at %i\n", group - end1);
		memmove(used - sizeof(*group), used, (void *)(group + 1) - used);
		*group = (struct group){ .loghi = loghi, .count = 0 };
		used -= sizeof(*group);
		end1--;
		entries--;
		leaf->groups++;
	}
	/* find entry position */
	struct entry *end2 = --entries - group->count, *entry;
	for (entry = entries; entry > end2; entry--)
		if (loglo <= entry->loglo)
			break;
	/* insert new entry if no match  */
	if (entry == end2 || loglo < entry->loglo) {
		printf("insert 0x%Lx at %i in group %i\n", target, entries - entry, group - end1);
		memmove(used - sizeof(*entry), used, (void *)(entry + 1) - used);
		*entry = (struct entry){ .loglo = loglo, .limit = !group->count ? 0 : (entry + 1)->limit };
		used -= sizeof(*entry);
		end2--;
		group->count++;
	}
	/* insert the extent */
	struct extent *where = extents + entry->limit;
	memmove(where + 1, where, (void *)leaf + leaf->free - (void *)where);
	*where = extent;
	/* bump entry and successor limits */
	while (entry > end2)
		(entry--)->limit++;
	/* clean up */
	leaf->used = (void *)used - (void *)leaf;
	leaf->free += sizeof(*where);
	return 0;
}

struct leaf *new_leaf(void)
{
	struct leaf *leaf = malloc(blocksize);
	*leaf = (struct leaf){ .magic = 0x1eaf, .groups = 0, .free = sizeof(struct leaf), .used = blocksize };
	return leaf;
}

int main(int argc, char *argv[])
{
	struct leaf *leaf = new_leaf();
	printf("--- leaf test ---\n");
	unsigned hi = 1 << 24, hi2 = 2 * hi;
	unsigned targets[] = { 0x11, 0x33, 0x22, hi2 + 0x44, hi2 + 0x55, hi2 + 0x44, hi + 0x33, 0x99 }, next = 0;
	leaf_dump(leaf);
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x111 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x222 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x333 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x444 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x555 });
	leaf_insert(leaf, targets[next++], (struct extent){ .block = 0x666 });
	leaf_insert(leaf, targets[next], (struct extent){ .block = 0x777 });
	leaf_insert(leaf, targets[next], (struct extent){ .block = 0x888 });
	leaf_insert(leaf, targets[next], (struct extent){ .block = 0x999 });
	leaf_dump(leaf);
	for (int i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
		unsigned target = targets[i];
		unsigned count;
		unsigned found = leaf_lookup(leaf, target, &count);
		printf("lookup 0x%x, found [%i/%i]\n", target, found, count );
	}
	return 0;
}
