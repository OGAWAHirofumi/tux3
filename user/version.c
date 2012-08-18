/*
 * Versioned pointer operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#define vecmove(d, s, n) memmove(d, s, (n) * sizeof(*(d)))
#define vecset(d, v, n) memset(d, v, (n) * sizeof(*(d)))
#define error(string, args...) do { printf(string, ##args); printf("!\n"); exit(99); } while (0)
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define trace_off(cmd)
#define trace_on(cmd) cmd
#define PACKED __attribute__ ((packed))

#if 1
void hexdump(void *data, unsigned size)
{
	while (size) {
		unsigned char *p;
		int w = 16, n = size < w? size: w, pad = w - n;
		printf("%p:  ", data);
		for (p = data; p < (unsigned char *)data + n;)
			printf("%02hx ", *p++);
		printf("%*.s  \"", pad*3, "");
		for (p = data; p < (unsigned char *)data + n;) {
			int c = *p++;
			printf("%c", c < ' ' || c > 127 ? '.' : c);
		}
		printf("\"\n");
		data += w;
		size -= n;
	}
}
#endif

/* Careful about bitops on kernel port - need to use *_bit_le(). */
bool get_bit(unsigned char *bitmap, unsigned i)
{
	return (bitmap[i >> 3] >> (i & 7)) & 1;
}

void set_bit(unsigned char *bitmap, unsigned i)
{
	bitmap[i >> 3] |= (1 << (i & 7));
}

void reset_bit(unsigned char *bitmap, unsigned i)
{
	bitmap[i >> 3] &= ~(1 << (i & 7));
}

#define LABEL_BITS 8
#define CHUNK_BITS 54
#define MAXVERSIONS (1 << LABEL_BITS)

typedef uint16_t version_t;
typedef uint16_t label_t;
typedef uint64_t chunk_t;
typedef unsigned tag_t;
typedef unsigned char bitmap_t;

struct element { label_t label: LABEL_BITS; chunk_t chunk: CHUNK_BITS; } PACKED;
struct version { tag_t tag; label_t parent; bool used, ghost, present, pathmap, nearmap; };

struct sb {
	struct version table[MAXVERSIONS];
	label_t *child_index[MAXVERSIONS];
	label_t child_count[MAXVERSIONS];
	label_t children[MAXVERSIONS];
	label_t ordmap[MAXVERSIONS];
	label_t version_count, active_count;
	unsigned char pathmap[MAXVERSIONS][MAXVERSIONS >> 3];
	unsigned char nearmap[MAXVERSIONS][MAXVERSIONS >> 3];
	label_t brood[MAXVERSIONS]; /* children present in element list per parent */
};

label_t get_child(struct sb *sb, label_t parent, unsigned i)
{
	return sb->child_index[parent][i];
}

label_t get_parent(struct sb *sb, label_t child)
{
	struct version *table = sb->table;
	return table[child].parent;
}

label_t get_root(struct sb *sb)
{
	assert(sb->child_count[0]);
	return sb->children[0];
}

label_t is_ghost(struct sb *sb, label_t version)
{
	struct version *table = sb->table;
	return table[version].ghost;
}

void show_table(struct sb *sb)
{
	struct version *table = sb->table;
	for (int i = 0; i < sb->version_count; i++) {
		printf("%i: ", i);
		if (!table[i].used)
			printf("(free)");
		else if (!i)
			printf("(origin)");
		else {
			printf("<- ");
			if (!get_parent(sb, i))
				printf("root");
			else
				printf("%i", get_parent(sb, i));
			if (!is_ghost(sb, i)) // 0 should be a ghost
				printf(" '%i'", table[i].tag);
		}
		printf("\n");
	}
}

int count_table(struct sb *sb)
{
	struct version *table = sb->table;
	int total = 0;
	for (int i = 0; i < sb->version_count; i++)
		total += table[i].used;
	return total;
}

unsigned cycle;
unsigned element_count;
struct element elements[1000];

void show_elements(struct sb *sb)
{
	printf("%i elements: ", element_count);
	for (int i = 0; i < element_count; i++)
		printf("[%i, %Lu] ", elements[i].label, (chunk_t)elements[i].chunk);
	printf("\n");
}

void show_index(struct sb *sb)
{
	printf("child index: ");
	for (int i = 0; i < sb->version_count; i++)
		printf("%i:%u ", i, sb->children - sb->child_index[i]);
	printf("\n");
}

int show_subtree(struct sb *sb, version_t version, int depth, version_t target)
{
	struct version *table = sb->table;
	assert(depth < MAXVERSIONS);
	printf("%*s(%i) ", 3 * depth, "", version);
	if (!is_ghost(sb, version))
		printf("'%i'", table[version].tag);
	else printf("~%i", sb->child_count[version]);
	for (int i = 0; i < element_count; i++)
		if (elements[i].label == version)
			printf(" [%Lu]", (chunk_t)elements[i].chunk);
	printf("%s\n", target == version ? " <==" : "");
	int total = 0;
	for (int i = 0; i < sb->child_count[version]; i++)
		total += show_subtree(sb, get_child(sb, version, i), depth + 1, target);
	return total + 1;
}

void show_tree(struct sb *sb)
{
	printf("%u versions\n", sb->child_count[0] ? show_subtree(sb, get_root(sb), 0, 0) : 0);
}

int count_subtree(struct sb *sb, label_t version, int depth)
{
	struct version *table = sb->table;
	if (depth > MAXVERSIONS)
		return MAXVERSIONS;
	assert(table[version].used);
	int total = 0;
	for (int i = 0; i < sb->child_count[version]; i++)
		total += count_subtree(sb, get_child(sb, version, i), depth + 1);
	return total + 1;
}

int count_tree(struct sb *sb)
{
	return count_subtree(sb, 0, 0);
}

void order_tree(struct sb *sb, label_t version, int order)
{
	sb->ordmap[version] = order;
	for (int i = 0; i < sb->child_count[version]; i++)
		order_tree(sb, get_child(sb, version, i), order + 1);
}

/* Chunk allocation */

#define MAXCHUNKS MAXVERSIONS

typedef unsigned data_t;
data_t snapdata[MAXCHUNKS], orgdata = 0x1234;
data_t checkdata[MAXVERSIONS];
bool allocmap[MAXCHUNKS];
chunk_t nextchunk;

chunk_t new_chunk(struct sb *sb, data_t data)
{
	for (int i = 0; i < MAXCHUNKS; i++, nextchunk++) {
		if (nextchunk == MAXCHUNKS)
			nextchunk = 0;
		if (!allocmap[nextchunk])
			goto found;
	}
	error("out of chunks");
found:
	assert(!allocmap[nextchunk]);
	allocmap[nextchunk] = 1;
	snapdata[nextchunk] = data;
	return nextchunk++;

}

void free_chunk(struct sb *sb, chunk_t chunk)
{
	assert(allocmap[chunk]);
	allocmap[chunk] = 0;
}

/* Version allocation */

label_t new_version(struct sb *sb, label_t parent, uint32_t tag)
{
	struct version *table = sb->table;
	int version;
	for (version = 1; version < sb->version_count; version++)
		if (!table[version].used)
			goto recycle;
	int last = sb->version_count - 1;
	sb->child_index[sb->version_count] = sb->version_count ? sb->child_index[last] + sb->child_count[last] : sb->children;
	version = sb->version_count++;
recycle:
	table[version] = (struct version){ .parent = parent, .tag = tag, .used = 1 };
	assert(!sb->child_count[version]);
	sb->active_count++;
	return version;
}

void free_version(struct sb *sb, label_t version)
{
	assert(sb->table[version].used);
	sb->table[version].parent = 0;
	sb->table[version].used = 0;
	sb->active_count--;
}

#if 0
void extract_children(struct sb *sb) // O(n^2)
{
	unsigned total = 0;
	memset(sb->child_count, 0, sizeof(sb->child_count));
	for (int parent = 0; parent < sb->version_count; parent++) {
		sb->child_index[parent] = sb->children + total;
		for (int child = 0; child < sb->version_count; child++)
			if (get_parent(sb, child) == parent) {
				sb->children[total++] = child;
				sb->child_count[parent]++;
			}
	}
}
#else
/*
 * Three pass O(versions) tree extract
 *
 * 1: walk the table incrementing child counts of parents
 * 2: accumulate the counts to create the index, clear the counts
 * 3: walk the table filling in the children using the index
 */
void extract_children(struct sb *sb) // O(n^2)
{
	struct version *table = sb->table;
	unsigned total = 0;
	vecset(sb->child_count, 0, sb->version_count);
	for (int i = 1; i < sb->version_count; i++)
		if (table[i].used)
			sb->child_count[get_parent(sb, i)]++;
	for (int i = 0; i < sb->version_count; i++) {
		sb->child_index[i] = sb->children + total;
		total += sb->child_count[i];
	}
	vecset(sb->child_count, 0, sb->version_count);
	for (int i = 1; i < sb->version_count; i++)
		if (table[i].used) {
			version_t parent = get_parent(sb, i);
			sb->child_index[parent][sb->child_count[parent]++] = i;
		}
}
#endif

/* Version tree editing */

void add_element(struct sb *sb, version_t label, chunk_t chunk)
{
	printf("new element [%u, %Lu]\n", label, chunk);
	assert(element_count < MAXVERSIONS);
	elements[element_count++] = (struct element){ .label = label, .chunk = chunk };
}

bitmap_t *need_path(struct sb *sb, version_t target)
{
	if (!sb->table[target].pathmap) {
		trace_off(printf("load pathmap for (%u)\n", target);)
		memset(sb->pathmap[target], 0, sizeof(sb->pathmap[target]));
		for (label_t v = target; v; v = get_parent(sb, v))
			set_bit(sb->pathmap[target], v);
		sb->table[target].pathmap = 1;
	}
	return sb->pathmap[target];
}

void invalidate_path(struct sb *sb, version_t version)
{
	struct version *table = sb->table;
	assert(version < MAXVERSIONS);
	assert(table[version].used);
	table[version].pathmap = 0;
	for (int i = 0; i < sb->child_count[version]; i++)
		invalidate_path(sb, get_child(sb, version, i));
}

/*
 * Store the ord numbers in the version table.  Per-version bitmap specifies
 * whether any given version is on the path to root.  Walk the element list
 * looking for the label on the path with the highest ord.
 */
struct element *lookup_element(struct sb *sb, version_t target)
{
	int high = 0;
	bitmap_t *path = need_path(sb, target);
	struct element *found = NULL;
	for (struct element *e = elements; e < elements + element_count; e++)
		if (get_bit(path, e->label) && sb->ordmap[e->label] > high)
			high = sb->ordmap[(found = e)->label];
	return found;
}

/*
 * O(e) same chunk test (for version difference)
 *
 * Ord numbers stored in version table.
 * Walk the element list
 *   Find the element with the highest ord for version1
 *   Find the element with the highest ord for version2
 * The versions inherit the same chunk iff the same element was found
 */

bool same_chunk(struct sb *sb, version_t version1, version_t version2)
{
	struct element *e1 = NULL, *e2 = NULL;
	unsigned high1 = 0, high2 = 0;
	bitmap_t *path1 = need_path(sb, version1);
	bitmap_t *path2 = need_path(sb, version2);
	for (struct element *e = elements; e < elements + element_count; e++) {
		if (get_bit(path1, e->label) && sb->ordmap[e->label] > high1)
			high1 = sb->ordmap[(e1 = e)->label];
		if (get_bit(path2, e->label) && sb->ordmap[e->label] > high2)
			high2 = sb->ordmap[(e2 = e)->label];
	}
	return e1 == e2;
}

unsigned count_near(struct sb *sb, version_t target)
{
	struct version *table = sb->table;
	if (!table[target].nearmap) {
		trace_off(printf("load nearmap for (%u)\n", target);)
		memset(sb->nearmap[target], 0, sizeof(sb->nearmap[target]));
		for (int i = 0; i < sb->child_count[target]; i++)
			set_bit(sb->nearmap[target], get_child(sb, target, i));
		set_bit(sb->nearmap[target], target);
		table[target].nearmap = 1;
	}
	bitmap_t *map = sb->nearmap[target];
	int present = 0;
	for (struct element *e = elements; e < elements + element_count; e++)
		present += get_bit(map, e->label);
	assert(present <= sb->child_count[target] + 1);
	return present;
}

struct element *find_element(struct sb *sb, version_t target)
{
	for (int i = 0; i < element_count; i++)
		if (elements[i].label == target)
			return &elements[i];
	return NULL;
}

void set_present(struct sb *sb, bool flag)
{
	struct version *table = sb->table;
	for (struct element *e = elements; e < elements + element_count; e++)
		table[e->label].present = flag;
}

bool is_present(struct sb *sb, version_t version)
{
	struct version *table = sb->table;
	return table[version].present;
}

/*
 * The orphan test is used in snapshot write and element delete to
 * identify any new orphans created as a result of a write that creates an
 * exclusive element for the only heir of the ghost element, or a
 * delete that removes the only heir and does not promote a new heir.
 *
 * To perform this test in O(elements) time:
 *
 * First, identify a subtree of the version tree consisting only of ghost
 * versions in interior nodes and visible versions at terminal nodes,
 * descending from the ghost ancestor of the victim version nearest the
 * root and having no visible versions or present elements between itself
 * and the victim.  Call each interior node of that subtree a "nexus",
 * which must have more than one child because it is a ghost.  This step
 * is done once, prior to a full-tree version delete pass.
 *
 * The interesting question is whether a ghost element is inherited
 * by any visible version that does not appear in the same element list.
 * If not, then the ghost element is an orphan that must be deleted.
 * This can be computed efficiently using a bottom up approach with a
 * single pass through the element list.  At each nexus keep a count of
 * the children of the nexus that are known not to inherit from that
 * nexus.  Call that the blocked count.  Zero the blocked counts then:
 *
 *    For each element in the element list:
 *       If the version labeled by the element is in the ghost
 *       tree then increment the blocked count of the nexus parent
 *
 *       If the blocked count is now equal to the number of children
 *       of the nexus then repeat from the preceding step
 *
 * At completion, if the blocked count of the ghost ancestor is equal to
 * its child count then the ghost element is an orphan, otherwise not.
 *
 * Not yet implemented.
 */

int show_heirs_(struct sb *sb, version_t parent)
{
	int heirs = 0;
	for (int i = 0; i < sb->child_count[parent]; i++) {
		version_t child = get_child(sb, parent, i);
		if (!is_present(sb, child)) {
			bool heir = !is_ghost(sb, child);
			if (heir)
				printf("%u ", child);
			heirs += show_heirs_(sb, child) + heir;
		}
	}
	return heirs;
}

void show_heirs(struct sb *sb, version_t parent)
{
	set_present(sb, 1);
	printf("heirs of %u: ", parent);
	printf("(%i)\n", show_heirs_(sb, parent));
	set_present(sb, 0);
}

int count_heirs(struct sb *sb, version_t parent)
{
	int heirs = 0;
	for (int i = 0; i < sb->child_count[parent]; i++) {
		version_t child = get_child(sb, parent, i);
		if (!is_present(sb, child))
			heirs += count_heirs(sb, child) + !is_ghost(sb, child);
	}
	return heirs;
}

int inherited(struct sb *sb, version_t version)
{
	set_present(sb, 1);
	int heirs = count_heirs(sb, version);
	set_present(sb, 0);
	return heirs;
}

label_t *find_child_pos(struct sb *sb, version_t parent, version_t child, unsigned count)
{
	/* insert sorted for cosmetic reasons */
	label_t *p = sb->child_index[parent];
	for (int i = 0; i < count; i++, p++)
		if (child < *p)
			break;
	return p;
}

label_t *find_child(struct sb *sb, version_t parent, version_t child)
{
	for (int i = 0; i < sb->child_count[parent]; i++)
		if (get_child(sb, parent, i) == child)
			return sb->child_index[parent] + i;
	error("child not found");
}

void insert_child(struct sb *sb, version_t parent, version_t child)
{
	struct version *table = sb->table;
	label_t *p = find_child_pos(sb, parent, child, sb->child_count[parent]);
	vecmove(p + 1, p, sb->children + sb->version_count - p - 1);
	*p = child;
	for (int i = parent + 1; i < sb->version_count; i++)
		sb->child_index[i]++;
	sb->child_count[parent]++;
	table[child].parent = parent;
	table[parent].nearmap = 0;
	order_tree(sb, get_root(sb), 1); // overkill
}

void remove_child(struct sb *sb, version_t child)
{
	struct version *table = sb->table;
	label_t parent = get_parent(sb, child);
	label_t *p = find_child(sb, parent, child);
	vecmove(p, p + 1, sb->children + sb->version_count - p - 1);
	for (int i = parent + 1; i < sb->version_count; i++)
		sb->child_index[i]--;
	sb->child_count[parent]--;
	table[parent].nearmap = 0;
}

void replace_child(struct sb *sb, version_t old, version_t new)
{
	version_t parent = get_parent(sb, old);
	version_t *p1 = sb->child_index[parent], *p2 = find_child(sb, parent, old);
	vecmove(p2, p2 + 1, p1 + sb->child_count[parent] - p2 - 1);
	p2 = find_child_pos(sb, parent, new, sb->child_count[parent] - 1);
	vecmove(p2 + 1, p2, p1 + sb->child_count[parent] - p2 - 1);
	*p2 = new;
	sb->table[new].parent = parent;
	free_version(sb, old);
	sb->table[parent].nearmap = 0;
}

void promote_child(struct sb *sb, version_t child)
{
	version_t parent = get_parent(sb, child);
	printf("promote (%u) over (%u)\n", child, parent);
	assert(sb->child_count[parent] == 1);
	remove_child(sb, child);
	replace_child(sb, parent, child);
	invalidate_path(sb, child);
	order_tree(sb, get_root(sb), 1); // overkill
}

/*
 * Ghost element inheritance
 *
 * Any ghost element inherited only by ghosts may be deleted.
 *
 * If a target with more than one child, an element and no heirs is deleted
 * then the element may be deleted.
 *
 * Replacing a target with one child and no element by its child with no
 * heirs reduces heirs of the parent.
 *
 * If a target has no children and no element then removing it or replacing
 * its ghost parent with no element by a sibling of the target with no
 * heirs reduces heirs of the parent.
 *
 * If heirs are reduced, a search for a ghost ancestor with an uninherited
 * element must be performed.
 */

/*
 * O(elements) element delete
 *
 * 1: walk the element list incrementing per parent present child counts
 * 2: walk the list deleting target elements where present equals child count
 * 3: walk the list clearing present entries for the next time round
 */

bool delete_elements(struct sb *sb, version_t target, version_t parent)
{
	struct version *table = sb->table;
	printf("delete (%u) (%i children)\n", target, sb->child_count[target]);
	struct element *limit = elements + element_count, *save = elements, *kill = NULL;
	for (struct element *from = elements; from < limit; from++)
		sb->brood[get_parent(sb, from->label)]++;
	set_present(sb, 1);
	if (!is_present(sb, target)) {
		/* kill orphans */
		version_t ancestor = parent;
		while (!is_present(sb, ancestor) && ancestor)
			ancestor = get_parent(sb, ancestor);
		if (ancestor && is_ghost(sb, ancestor) && is_present(sb, ancestor) && !count_heirs(sb, ancestor))
			kill = find_element(sb, ancestor);
	}
	if (kill)
		printf("kill orphan %u\n", kill->label);
	if (!is_ghost(sb, parent))
		parent = 0;
	for (struct element *from = elements; from < limit; from++) {
		version_t label = from->label;
		if (from == kill)
			goto free;
		if (label == target || label == parent) {
			if (sb->child_count[label] == sb->brood[label])
				goto free;
			if (sb->child_count[label] == 1) {
				if (!count_heirs(sb, label))
					goto free;
				printf("relabel %i as %i\n", label, get_child(sb, label, 0));
				table[label].present = 0;
				label = from->label = get_child(sb, label, 0);
				table[label].present = 1;
				goto keep;
			}
			if (sb->child_count[label] > 1 && !count_heirs(sb, label))
				goto free;
			goto keep;
		}
keep:
		*save++ = *from;
		continue;
free:
		table[label].present = 0;
		printf("free [%i, %Li]\n", from->label, (chunk_t)from->chunk);
		free_chunk(sb, from->chunk);
		element_count--;
	}
	set_present(sb, 0);
	for (save = elements; save < elements + element_count; save++)
		sb->brood[get_parent(sb, save->label)] = 0;
	return parent && sb->child_count[parent] == 1;
}

/* External operations */

int find_tag(struct sb *sb, tag_t tag)
{
	struct version *table = sb->table;
	for (int version = 1; version < sb->version_count; version++)
		if (!is_ghost(sb, version) && table[version].tag == tag)
			return version;
	error("invalid snapshot '%u'", tag);
	return 0;
}

void show_tree_with_target(struct sb *sb, tag_t tag)
{
	version_t target = tag == -1 ? 0 : find_tag(sb, tag);
	int total = sb->child_count[0] ? show_subtree(sb, get_root(sb), 0, target) : 0;
	printf("%u versions\n", total);
}

void snapshot_delete(struct sb *sb, tag_t tag)
{
	//if (cycle == 75109) show_tree_with_target(tag);
	struct version *table = sb->table;
	version_t target = find_tag(sb, tag);
	memset(sb->brood, 0, sizeof(sb->brood));
	table[target].tag = 0;
	table[target].ghost = 1; /* does not inherit ghost element */
	version_t parent = get_parent(sb, target);
	switch (sb->child_count[target]) {
	case 0:
		remove_child(sb, target); /* no relabel to deleted child */
		sb->table[target].parent = 0;
		if (delete_elements(sb, target, parent))
			promote_child(sb, get_child(sb, parent, 0));
		free_version(sb, target);
		break;
	case 1:
		delete_elements(sb, target, parent);
		promote_child(sb, get_child(sb, target, 0));
		break;
	default:
		delete_elements(sb, target, parent);
	}
}

void snapshot_of_snapshot(struct sb *sb, tag_t tag, tag_t parent_tag)
{
	label_t parent = find_tag(sb, parent_tag);
	label_t child = new_version(sb, parent, tag);
	assert(!sb->child_count[child]);
	insert_child(sb, parent, child);
	order_tree(sb, get_root(sb), 1); // overkill
}

void snapshot_of_origin(struct sb *sb, tag_t tag)
{
	label_t root = new_version(sb, 0, tag);
	if (!sb->child_count[0]) {
		insert_child(sb, 0, root);
		return;
	}
	insert_child(sb, root, get_child(sb, 0, 0));
	sb->children[0] = root;
	invalidate_path(sb, root);
	order_tree(sb, get_root(sb), 1); // overkill
}

data_t snapshot_read(struct sb *sb, tag_t tag)
{
	struct element *found = lookup_element(sb, find_tag(sb, tag));
	//printf("read (%u), chunk %Li\n", find_tag(tag), found->chunk);
	return found ? snapdata[found->chunk] : orgdata;
}

void snapshot_write(struct sb *sb, tag_t tag, data_t data)
{
	struct version *table = sb->table;
	label_t target = find_tag(sb, tag);
	printf("write 0x%x to snapshot %i (%u)\n", data, tag, target);
	struct element *e;

	/* has unique element? */
	if (count_near(sb, target) == sb->child_count[target] + 1) {
		e = find_element(sb, target);
		goto rewrite;
	}

	/* create implicit version? */
	if (sb->child_count[target]) {
		label_t child = new_version(sb, target, tag);
		printf("implicit version (%u) of (%u)\n", child, target);
		insert_child(sb, target, child);
		table[target].ghost = 1;
		target = child;
	}

	/* relabel orphan? */
	set_present(sb, 1);
	label_t ancestor = get_parent(sb, target);
	while (!is_present(sb, ancestor) && is_ghost(sb, ancestor))
		ancestor = get_parent(sb, ancestor);
	bool relabel = is_ghost(sb, ancestor) && count_heirs(sb, ancestor) == 1;
	set_present(sb, 0);
	if (relabel) {
		printf("relabel (%u) element to (%u)!\n", ancestor, target);
		e = find_element(sb, ancestor);
		e->label = target;
		goto rewrite;
	}

	/* new element */
	chunk_t chunk = new_chunk(sb, data);
	add_element(sb, target, chunk);
	checkdata[target] = snapdata[chunk] = data;
	return;
rewrite:
	printf("rewrite chunk %Lu to 0x%x\n", (chunk_t)e->chunk, data);
	checkdata[target] = snapdata[e->chunk] = data;
	return;
}

void origin_write(struct sb *sb, data_t data)
{
	printf("write 0x%x to origin\n", data);
	if (inherited(sb, 0))
		add_element(sb, get_root(sb), new_chunk(sb, orgdata));
	orgdata = data;
}

void fuzz_test(struct sb *sb, unsigned cycles)
{
	struct version *table = sb->table;
	tag_t snap[MAXVERSIONS], tag, newtag = 1000;
	unsigned culprit = -1, snaps = 0;
	char *why;

	for (cycle = 1; cycle <= cycles; cycle++) {
		printf("--- cycle %i ---\n", cycle);
		if (!snaps || rand() % 5 == 0) {
			if (!snaps || (snaps < MAXVERSIONS / 2 && rand() % 2000000 < 1000000)) {
				/* Randomly create snapshot */
				tag = snap[snaps] = newtag++;
				if (!snaps || rand() % 20 == 0) {
					printf("create snapshot %u of origin\n", tag);
					snapshot_of_origin(sb, tag);
					checkdata[find_tag(sb, tag)] = orgdata;
				} else {
					tag_t parent = snap[rand() % snaps];
					printf("create snapshot '%u' of '%u'\n", tag, parent);
					snapshot_of_snapshot(sb, tag, parent);
					checkdata[find_tag(sb, tag)] = snapshot_read(sb, parent);
				}
				snaps++;
			} else {
				/* Randomly delete snapshot */
				int which = rand() % snaps;
				printf("delete snapshot '%u'\n", snap[which]);
				snapshot_delete(sb, snap[which]);
				snap[which] = snap[--snaps];
				tag = -1;
			}
		} else {
			/* Write to random snapshot */
			data_t data = rand();
			if (rand() % 20 == 0) {
				tag = -1;
				origin_write(sb, data);
			} else {
				tag = snap[rand() % snaps];
				snapshot_write(sb, tag, data);
			}
		}
		/* Validate version table */
		why = "version 0 corrupt";
		if (is_ghost(sb, 0) || sb->child_count[0] > 1)
			goto eek;
		for (int version = 0; version < sb->version_count; version++) {
			if (!table[version].used)
				continue;
			why = "present flag should be clear for %u";
			if (table[version].present) {
				culprit = version;
				goto eek;
			}
			why = "ghost %u has less than two children";
			if (is_ghost(sb, version) && sb->child_count[version] < 2) {
				culprit = version;
				goto eek;
			}
		}
		/* Validate version tree */
		why = "tree has a cycle";
		int counted = count_tree(sb);
		if (counted == MAXVERSIONS)
			goto eek;
		why = "wrong number of versions in version tree";
		if (counted != sb->active_count)
			goto eek;
		/* Validate element list */
		bool member[MAXVERSIONS] = { };
		for (int i = 0; i < element_count; i++) {
			label_t version = elements[i].label;
			//printf("[%i, %Lu]\n", version, (chunk_t)elements[i].chunk);
			why = "invalid element label";
			if (version == 0 || version > MAXVERSIONS)
				goto eek;
			why = "deleted version in element list";
			if (!table[version].used)
				goto eek;
			why = "multiple elements with same label";
			if (member[version])
				goto eek;
			why = "ghost %u has orphan element";
			if (is_ghost(sb, version) && !inherited(sb, version)) {
				culprit = version;
				goto eek;
			}
			member[version] = 1;
		}
		/* Validate snapshot data */
		why = "snapshot %u has wrong data";
		for (int i = 0; i < snaps; i++) {
			data_t data = snapshot_read(sb, snap[i]);
			if (data != checkdata[find_tag(sb, snap[i])]) {
				culprit = tag = snap[i];
				goto eek;
			}
		}
		//if (cycle == 99999) { show_tree(sb); }
	}
	show_tree(sb);
	show_elements(sb);
	return;
eek:
	printf("--- Failed at cycle %u ---\n", cycle);
	show_tree_with_target(sb, tag);
	//show_table();
	printf("tree count = %u, table count = %u, active count = %u\n", count_tree(sb), count_table(sb), sb->active_count);
	show_elements(sb);
	if (culprit + 1)
		error(why, culprit);
	else
		error(why);
}

void same_test(struct sb *sb, version_t version1, version_t version2)
{
	printf("%u and %u are %s\n", version1, version2, same_chunk(sb, version1, version2) ? "the same" : "different");
}

int main(int argc, char *argv[])
{
	struct sb sbb = { }, *sb = &sbb;
	struct version *table = sb->table;
	label_t v0 = new_version(sb, -1, 0);

#if 1
	srand(12345);
	fuzz_test(sb, argc > 1 ? atoi(argv[1]) : 10000);
//	same_test(sb, 3, 4);
//	show_heirs(sb, 22);
	exit(0);
#endif

	tag_t nexttag = 1001;
	label_t v1 = v1 = new_version(sb, v0, nexttag++);
	label_t v2 = v2 = new_version(sb, v1, nexttag++);
	label_t v3 = v3 = new_version(sb, v2, nexttag++);
	extract_children(sb);
	show_tree(sb);
	exit(0);
#if 0
	show_table();
	extract_children();
	show_tree();
	hexdump(child_count, 16);
	hexdump(child_index, 16);
	hexdump(children, 16);
	promote_child(v3);
	//remove_version(v5);
	//delete_snapshot(2000);
	//nested_snapshot(123, 2005);
	//snapshot_of_origin(123);
	show_table();
	hexdump(child_count, 16);
	hexdump(child_index, 16);
	hexdump(children, 16);
	show_tree();
	extract_children();
	show_tree();
	return 0;
	free_version(v1);
	free_version(v4);
	show_table();
	return 0;
#endif
	extract_children(sb);
	label_t target = v2;
	tag_t tag = table[target].tag;
	add_element(sb, v2, new_chunk(sb, 0));
	show_elements(sb);
	show_tree(sb);
	printf("data = %u\n", snapshot_read(sb, tag));
	snapshot_write(sb, tag, 0x333);
	show_tree(sb);
	snapshot_write(sb, 1003, 0x666);
	show_tree(sb);
//	hexdump(snapdata, 16);
//	origin_write(666);
//	origin_write(777);
//	snapshot_write(table[target].tag, 555);
	show_elements(sb);
	hexdump(snapdata, 32);
	printf("data = 0x%x, orgdata = 0x%x\n", snapshot_read(sb, tag), orgdata);
	printf("v3 data = 0x%x\n", snapshot_read(sb, table[v3].tag));
	show_tree(sb);
	hexdump(sb->nearmap[v2], 16);
//	delete_elements((label_t[]){ v7 }, 1);
	snapshot_delete(sb, 1003);
	show_tree(sb);
	show_elements(sb);
	snapshot_delete(sb, 1001);
	show_tree(sb);
	show_elements(sb);
	snapshot_delete(sb, 1002);
	show_tree(sb);
	show_elements(sb);
	snapshot_of_origin(sb, 1009);
	show_tree(sb);
	show_elements(sb);
	printf("data = 0x%x, orgdata = 0x%x\n", snapshot_read(sb, 1002), orgdata);
	hexdump(sb->child_index, 16);
	exit(0);

	label_t v4 = v4 = new_version(sb, v1, nexttag++);
	label_t v5 = v5 = new_version(sb, v4, nexttag++);
	label_t v6 = v6 = new_version(sb, v4, nexttag++);
	add_element(sb, v5, new_chunk(sb, 0));
	add_element(sb, v6, new_chunk(sb, 0));
#if 0
	load_nearmap(v4);
	hexdump(sb->nearmap[v4], 16);
	return 0;
#endif

	return 0;
}
