/* (c) 2008 Daniel Phillips <phillips@phunq.net>, licensed under GPL v2 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "hexdump.c"

#define error(string, args...) do { printf(string, ##args); printf("!\n"); exit(99); } while (0)
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t inum_t;

struct ileaf { u16 magic, count; inum_t inum; char table[]; };

unsigned blocksize = 4096;

/*
 * inode leaf format
 *
 * A leaf has a small header followed by a table of extents.  A vector of
 * offsets within the block grows down from the top of the leaf towards the
 * top of the extent table, indexed by the difference between inum and
 * leaf->inum, the base inum of the table block.
 */

struct ileaf *ileaf_create(void)
{
	struct ileaf *ileaf = malloc(blocksize);
	*ileaf = (struct ileaf){ .magic = 0x90de };
	return ileaf;
}

void ileaf_destroy(struct ileaf *leaf)
{
	assert(leaf->magic == 0x90de);
	free(leaf);
}

unsigned ileaf_used(struct ileaf *leaf)
{
	u16 *dict = (void *)leaf + blocksize, *base = dict - leaf->count;
	return (void *)dict - (void *)base + base == dict ? 0 : *base ;
}

unsigned ileaf_free(struct ileaf *leaf)
{
	return blocksize - ileaf_used(leaf) - sizeof(struct ileaf);
}

void ileaf_dump(struct ileaf *leaf)
{
	u16 *dict = (void *)leaf + blocksize, offset = 0, inum = leaf->inum;
	printf("%i inodes, %i free:\n", leaf->count, ileaf_free(leaf));
	//hexdump(dict - leaf->count, leaf->count * 2);
	for (int i = -1; i >= -leaf->count; i--, inum++) {
		int limit = dict[i], size = limit - offset;
		printf("  %i: ", inum);
		//printf("[%i] ", offset);
		if (size < 0)
			printf("<corrupt>\n");
		else if (size == 0)
			printf("<empty>\n");
		else
			hexdump(leaf->table + offset, size);
		offset = limit;
	}
}

void *ileaf_lookup(struct ileaf *leaf, inum_t inum, unsigned *size)
{
	assert(inum > leaf->inum);
	unsigned at = inum - leaf->inum;
	printf("inode at %i\n", at);
	assert(at < leaf->count);
	u16 *dict = (void *)leaf + blocksize, offset = (at ? *(dict - at) : 0);
	return (*size = *(dict - at - 1) - offset) ? leaf->table + offset : NULL;
}

int ileaf_check(struct ileaf *leaf)
{
	char *why;
	why = "not an inode table leaf";
	if (leaf->magic != 0x90de);
		goto eek;
	return 0;
eek:
	printf("%s!\n", why);
	return -1;
}

void ileaf_trim(struct ileaf *leaf) {
	u16 *dict = (void *)leaf + blocksize;
	while (leaf->count > 1 && *(dict - leaf->count) == *(dict - leaf->count + 1))
		leaf->count--;
	if (leaf->count == 1 && !*(dict - 1))
		leaf->count = 0;
}

void ileaf_split(struct ileaf *leaf, struct ileaf *dest, int fudge)
{
	u16 *dict = (void *)leaf + blocksize, *destdict = (void *)dest + blocksize;

	/* binsearch inum nearest middle */
	unsigned at = 1, hi = leaf->count;
	while (at < hi) {
		int mid = (at + hi) / 2;
		if (*(dict - mid) < (blocksize / 2) + fudge)
			at = mid + 1;
		else
			hi = mid;
	}
	printf("split at %i\n", (blocksize / 2) + fudge);

	/* should trim leading empty inodes on copy */
	unsigned split = *(dict - at), free = *(dict - leaf->count);
	printf("copy out %i bytes at %i\n", free - split, split);
	assert(free >= split);
	memcpy(dest->table, leaf->table + split, free - split);
	dest->count = leaf->count - at;
	veccopy(destdict - dest->count, dict - leaf->count, dest->count);
	for (int i = 1; i <= dest->count; i++)
		*(destdict - i) -= *(dict - at);
	dest->inum = leaf->inum + at;
	leaf->count = at;
	memset(leaf->table + split, 0, (char *)(dict - leaf->count) - (leaf->table + split));
	ileaf_trim(leaf);
}

void ileaf_merge(struct ileaf *leaf, struct ileaf *from)
{
	if (!from->count)
		return;
	u16 *dict = (void *)leaf + blocksize, *fromdict = (void *)from + blocksize;
	unsigned at = leaf->count, free = at ? *(dict - at) : 0;
	unsigned size = from->count ? *(fromdict - from->count) : 0;
	printf("copy in %i bytes %i %i\n", size, at + 1, at + from->count);
	memcpy(leaf->table + free, from->table, size);
	veccopy(dict - (leaf->count += from->count), fromdict - from->count, from->count);
	for (int i = at + 1; at && i <= at + from->count; i++)
		*(dict - i) += *(dict - at);
}

void *inode_expand(struct ileaf *leaf, inum_t inum, unsigned more, char fill)
{
	assert(inum > leaf->inum);
	u16 *dict = (void *)leaf + blocksize;
	unsigned at = inum - leaf->inum;

	/* extend with empty inodes */
	while (leaf->count <= at) {
		*(dict - leaf->count - 1) = leaf->count ? *(dict - leaf->count) : 0;
		leaf->count++;
	}

	u16 free = *(dict - leaf->count);
	unsigned offset = at ? *(dict - at) : 0, size = *(dict - at - 1) - offset;
	void *inode = leaf->table + offset;
	printf("expand inum %u at %i/%i by %i\n", at, offset, size, more);
	for (int i = at + 1; i <= leaf->count; i++)
		*(dict - i) += more;
	memmove(inode + size + more, inode + size, free - offset);
	memset(inode + size, fill, more);
	return inode;
}

int main(int argc, char *argv[])
{
	printf("--- test inode table leaf methods ---\n");
	struct ileaf *leaf = ileaf_create();
	struct ileaf *dest = ileaf_create();
	ileaf_dump(leaf);
	inode_expand(leaf, 3, 2, 'a');
	inode_expand(leaf, 4, 4, 'b');
	inode_expand(leaf, 6, 6, 'c');
	ileaf_dump(leaf);
	ileaf_split(leaf, dest, -(blocksize / 2));
	ileaf_dump(leaf);
	ileaf_dump(dest);
	ileaf_merge(leaf, dest);
	ileaf_dump(leaf);
	inode_expand(leaf, 3, 3, 'x');
	ileaf_dump(leaf);
	inode_expand(leaf, 8, 3, 'y');
	ileaf_dump(leaf);
	unsigned size = 0;
	char *inode = ileaf_lookup(leaf, 3, &size);
	hexdump(inode, size);
	ileaf_destroy(leaf);
	ileaf_destroy(dest);
	return 0;
}
