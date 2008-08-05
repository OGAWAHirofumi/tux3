/* (c) 2008 Daniel Phillips <phillips@phunq.net>, licensed under GPL v2 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#define error(string, args...) do { printf(string, ##args); printf("!\n"); exit(99); } while (0)
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

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

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t inum_t;

struct ileaf { u16 magic, count; u64 ibase; unsigned char table[]; };

unsigned blocksize = 4096;

/*
 * inode leaf format
 *
 * A leaf has a small header followed by a table of extents.  A vector of
 * offsets within the block grows down from the top of the leaf towards the
 * top of the extent table, indexed by the difference between inum and ibase,
 * the base inum of the table block.
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
	return (void *)dict - (void *)base + *base;
}

unsigned ileaf_free(struct ileaf *leaf)
{
	return blocksize - ileaf_used(leaf) - sizeof(struct ileaf);
}

void ileaf_dump(struct ileaf *leaf)
{
	u16 *dict = (void *)leaf + blocksize, offset = 0, inum = leaf->ibase;
	printf("%i inodes, free = %i:\n", leaf->count, ileaf_free(leaf));
	//hexdump(dict - leaf->count, leaf->count * 2);
	for (int i = -1; i >= -leaf->count; i--, inum++) {
		int limit = dict[i], size = limit - offset;
		printf("  %i: [%i] ", inum, offset);
		if (size < 0)
			printf("<corrupt>\n");
		else if (size == 0)
			printf("<empty>\n");
		else
			hexdump(leaf->table + offset, size);
		offset = limit;
	}
}

unsigned ileaf_lookup(struct ileaf *leaf, inum_t inum, unsigned *size)
{
	assert(inum > leaf->ibase);
	unsigned at = inum - leaf->ibase;
	if (at < leaf->count) {
		*size = 0;
		return 0;
	}
	u16 *dict = (void *)leaf + blocksize, offset = (at ? *(dict - at) : 0);
	return (*size = *(dict - at - 1) - offset) ? offset : 0;
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

int ileaf_init(struct ileaf *ileaf, inum_t inum)
{
	printf("allocate inode 0x%Lx\n", inum);
	return 0;
}


void ileaf_split(struct ileaf *leaf, struct ileaf *dest, int fudge)
{
	u16 *dict = (void *)leaf + blocksize, *destdict = (void *)dest + blocksize;

	/* find inum nearest block middle */
	unsigned at = 1, hi = leaf->count + 1;
	while (at < hi) {
		int mid = (at + hi) / 2;
		if (*(dict - mid) < (1 ? 5 : blocksize / 2))
			at = mid + 1;
		else
			hi = mid;
	}
	unsigned split = *(dict - at), free = *(dict - leaf->count);
	printf("split out %i..%i\n", split, free);
	assert(free > split);
	memcpy(dest->table, leaf->table + split, free - split);
	dest->count = leaf->count - at;
	veccopy(destdict - dest->count, dict - leaf->count, dest->count);
	leaf->count = at;
	for (int i = 1; i <= dest->count; i++)
		*(destdict - i) -= *(dict - at);
	dest->ibase = leaf->ibase + at;
}

void ileaf_merge(struct ileaf *leaf, struct ileaf *from)
{
	u16 *dict = (void *)leaf + blocksize, *fromdict = (void *)from + blocksize;
	unsigned at = leaf->count, free = *(dict - at), size = *(fromdict - from->count);
	printf("copy in %i bytes\n", size);
	memcpy(leaf->table + free, from->table, size);
	veccopy(dict - (leaf->count += from->count), fromdict - from->count, from->count);
	for (int i = at + 1; i <= at + from->count; i++)
		*(dict - i) += *(dict - at);
}

void *inode_expand(struct ileaf *leaf, inum_t inum, unsigned more, char fill)
{
	//unsigned size = 0, offset = ileaf_lookup(leaf, inum, &size);

	assert(inum > leaf->ibase);
	u16 *dict = (void *)leaf + blocksize;
	unsigned at = inum - leaf->ibase;

	/* extend dict if necessary */
	for (; leaf->count <= at; ) {
		*(dict - leaf->count - 1) = *(dict - leaf->count);
		leaf->count++;
	}
	ileaf_dump(leaf);

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
	ileaf_split(leaf, dest, 0);
	ileaf_dump(leaf);
	ileaf_dump(dest);
	ileaf_merge(leaf, dest);
	ileaf_dump(leaf);
	inode_expand(leaf, 3, 3, 'x');
	ileaf_dump(leaf);
	inode_expand(leaf, 8, 3, 'y');
	ileaf_dump(leaf);
	return 0;
}
