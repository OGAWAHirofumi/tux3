// gcc -std=gnu99 shard.c && ./a.out

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>
#include "hexdump.c"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef u16 be_u16;
typedef u32 be_u32;
typedef u64 be_u64;
typedef u8 be_u8;

typedef u64 hashkey_t;

/*
 * siphash
 */

#define ROTL(x,b) (u64)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (u8)((v)      ); (p)[1] = (u8)((v) >>  8); \
    (p)[2] = (u8)((v) >> 16); (p)[3] = (u8)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (u32)((v)      ));   \
  U32TO8_LE((p) + 4, (u32)((v) >> 32));

#define U8TO64_LE(p) \
  (((u64)((p)[0])      ) | \
   ((u64)((p)[1]) <<  8) | \
   ((u64)((p)[2]) << 16) | \
   ((u64)((p)[3]) << 24) | \
   ((u64)((p)[4]) << 32) | \
   ((u64)((p)[5]) << 40) | \
   ((u64)((p)[6]) << 48) | \
   ((u64)((p)[7]) << 56))

#define SIPROUND            \
  do {              \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while(0)

/* SipHash-2-4 */
u64 siphash(const u8 *in, unsigned len)
{
	const u8 k[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	/* "somepseudorandomlygeneratedbytes" */
	u64 v0 = 0x736f6d6570736575ULL;
	u64 v1 = 0x646f72616e646f6dULL;
	u64 v2 = 0x6c7967656e657261ULL;
	u64 v3 = 0x7465646279746573ULL;
	u64 b;
	u64 k0 = U8TO64_LE( k );
	u64 k1 = U8TO64_LE( k + 8 );
	u64 m;
	const u8 *end = in + len - (len % sizeof(u64));
	const int left = len & 7;
	b = ((u64)len) << 56;
	v3 ^= k1;
	v2 ^= k0;
	v1 ^= k1;
	v0 ^= k0;

	for (; in != end; in += 8) {
		m = U8TO64_LE( in );
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}

	switch (left) {
	case 7: b |= ( ( u64 )in[ 6] )  << 48;
	case 6: b |= ( ( u64 )in[ 5] )  << 40;
	case 5: b |= ( ( u64 )in[ 4] )  << 32;
	case 4: b |= ( ( u64 )in[ 3] )  << 24;
	case 3: b |= ( ( u64 )in[ 2] )  << 16;
	case 2: b |= ( ( u64 )in[ 1] )  <<  8;
	case 1: b |= ( ( u64 )in[ 0] ); break;
	case 0: break;
	}

	v3 ^= b;
	SIPROUND;
	SIPROUND;
	v0 ^= b;
	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	return v0 ^ v1 ^ v2  ^ v3;
}

#define BREAK asm("int3")

#if 1
#define assert(what) \
	do { \
		if (!(what)) { \
			printf("Failed assert(" #what ")!\n"); \
			BREAK; \
			exit(1); \
		} \
	} while (0)
#else
#define assert(what) do { } while (0)
#endif

#define COMBSORT(size, i, j, COMPARE, EXCHANGE) do { \
	unsigned gap = size, more, i; \
	do { \
		if (gap > 1) gap = gap*10/13; \
		if (gap - 9 < 2) gap = 11; \
		for (i = size - 1, more = gap > 1; i >= gap; i--) { \
			int j = i - gap; \
			if (COMPARE) { EXCHANGE; more = 1; } } \
	} while (more); \
} while (0)

#define EXCHANGE(a, b) do { typeof(a) _c_ = (a); (a) = (b); (b) = _c_; } while (0)

void errno_exit(void)
{
	printf("%s! (error %i)\n", strerror(errno), errno);
	BREAK;
	exit(1);
}

static inline unsigned align(unsigned n, unsigned maskbits)
{
	return n + (-n & (~(-1 << maskbits)));
}

/*
 * Each shard has a disk image, which is a fifo, and a cache object, which
 * is a hash table. The former supports efficient atomic update, and the
 * latter provides rapid existence tests for directory entry create.
 *
 * The shard cache resolves a phtree key in three steps:
 *
 *   1) high order bits determine which shard to look in
 *   2) middle bits select a bucket within the shard
 *   3) low order bits resolve collisions within the bucket
 *
 * So:
 *
 *   shardbits + bucketbits + lowbits = keybits (32 for phtree)
 *
 * We pack the dirent block number and the low key bits together into one 32
 * bit integer for compactness. (Alternatively, we could pack the key bits and
 * next pointer together, leaving a full 32 bits for block number, think about
 * it.) This gives 8 byte shard entries, so a shard big enough to cache one
 * million entries will be about 8 MB. This is not a hard limit: if the
 * shard does fill up we can either wait for the btree store process to reduce
 * the fifo size, or realloc the shard cache.
 *
 * To be continued...
 */

enum { filebacked = 1, blocksize_bits = 12 };

//#define PAGEVEC

/*
 * Bits for shard entry next pointer.
 * Max. 128MB per shard.
 */
#define SHARD_NEXTBITS		24
#define SHARD_NEXTSIZE		(1 << SHARD_NEXTBITS)
#define SHARD_NEXTMASK		((1ULL << SHARD_NEXTBITS) - 1)
#define SHARD_MAX_SIZE		(SHARD_NEXTSIZE * sizeof(struct shard_entry))

/*
 * FIFO blockbits.
 * Max. 4GB for dirent on 512b block.
 */
#define FIFO_BLOCKBITS		(32 - 9)
#define FIFO_BLOCKMASK		((1ULL << FIFO_BLOCKBITS) - 1)

/*
 * Single shard operations
 */

enum shardbits { keybits = 32, endlist = 0, noentry = SHARD_NEXTMASK, shard_entry_bits = 3 };

//struct fifo_entry { be_u32 key, block; };
struct fifo_entry { be_u64 key_block; }; // endian!!!

static unsigned fentry_block(struct fifo_entry *entry)
{
	return (entry->key_block >> 1) & FIFO_BLOCKMASK;
}

static unsigned fentry_is_insert(struct fifo_entry *entry)
{
	return entry->key_block & 1;
}

static unsigned fentry_key(struct fifo_entry *entry)
{
	return entry->key_block >> (FIFO_BLOCKBITS + 1);
}

static void set_fentry(struct fifo_entry *entry, unsigned block, int insert, unsigned key)
{
	entry->key_block = ((((u64)key << FIFO_BLOCKBITS) | block) << 1) | insert;
}

struct shard_fifo {
	u64 location:48, blocks:16;
	loff_t mapbase, window;
	u32 window_size;
	struct fifo_entry *base, *tail, *top; };

struct shard_entry { u64 key_block_next; };

struct shardmap;

struct shard {
	unsigned id, size, head, fence, count; // size in entries but fence in bytes! inconsistent?
	unsigned bucketbits, lowbits, lowmask, blockbits, blockmask, used, free;

	struct shardmap *map;
	struct shard_fifo fifo;
#ifdef PAGEVEC
	struct shard_entry *table[];
#else
	struct shard_entry table[];
#endif
};

#ifdef PAGEVEC
enum { PAGEBITS = 12, PAGESIZE = 1 << PAGEBITS, maxpagevec = (PAGESIZE - sizeof(struct shard)) / sizeof(void *) };

static void shard_populate(struct shard *shard, unsigned start, unsigned count)
{
	if (1)
		printf("populate pagevec start = %i, count = %i\n", start, count);
	for (unsigned i = start; i < start + count; i++) {
		assert(i < maxpagevec);
		shard->table[i] = malloc(PAGESIZE);
		assert(shard->table[i]);
	}
}
#endif

struct shardmap {
	unsigned mapbits, mapmask, shardbits, lowbits, fencebits;
	be_u32 fifomap_size, tailmap_size;
	int fd;
	loff_t base; unsigned window;
	unsigned *fifomap; // blocks relative to shardmap base
	unsigned *tailmap; // entries relative to fifo base
	struct shard *table[];
};

static inline hashkey_t map_keymask(struct shardmap *map)
{
	return ~(-1ULL << (map->mapbits + map->shardbits));
}

static inline hashkey_t shard_keymask(struct shardmap *map)
{
	return ~(-1ULL << (map->shardbits));
}

static unsigned shard_bytes(unsigned size)
{
#ifdef PAGEVEC
	return sizeof(struct shard) + maxpagevec * sizeof(void *);
#else
	return sizeof(struct shard) + size * sizeof(struct shard_entry);
#endif
}

static inline int shard_buckets(struct shard *shard)
{
	return 1 << shard->bucketbits;
}

struct shard_entry *shard_entry(struct shard *shard, unsigned i)
{
#ifdef PAGEVEC
	return shard->table[i >> 9] + (i & 511);
#else
	return shard->table + i;
#endif
}

static inline int entry_key(struct shard *shard, struct shard_entry *entry)
{
	return entry->key_block_next >> (shard->blockbits + SHARD_NEXTBITS);
}

static inline int entry_block(struct shard *shard, struct shard_entry *entry)
{
	return (entry->key_block_next >> SHARD_NEXTBITS) & shard->blockmask;
}

static inline int entry_next(struct shard *shard, struct shard_entry *entry)
{
	return entry->key_block_next & SHARD_NEXTMASK;
}

static inline void set_entry_next(struct shard *shard, struct shard_entry *entry, unsigned next)
{
	entry->key_block_next = (entry->key_block_next & ~SHARD_NEXTMASK) | next;
}

static inline void set_entry(struct shard *shard, struct shard_entry *entry, unsigned lowkey, unsigned block, unsigned next)
{
	entry->key_block_next = ((((u64)lowkey << shard->blockbits) | block) << SHARD_NEXTBITS) | next;
}

static inline int bucket_is_empty(struct shard *shard, unsigned i)
{
	return entry_next(shard, shard_entry(shard, i)) == noentry;
}

static unsigned shard_id(struct shard *shard)
{
	return shard->id;
}

static loff_t fifo_pos(struct shard *shard)
{
	return shard->map->base + shard->map->fifomap[shard->id];
}

static unsigned fifo_tail(struct shard *shard)
{
	return shard->head / sizeof(struct fifo_entry) + (shard->fifo.tail - shard->fifo.base);
}

static void shard_mmap(struct shard *shard, unsigned start, unsigned length)
{
	if (0)
		printf("map shard %i, pos = %Lx, length = %x\n",
			shard_id(shard), (long long)fifo_pos(shard) + shard->head, length);
	struct shard_fifo *fifo = &shard->fifo;
	struct fifo_entry *base = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, shard->map->fd, fifo_pos(shard) + start);
	if (base == MAP_FAILED)
		errno_exit();
	fifo->base = fifo->tail = base;
	fifo->top = (struct fifo_entry *)((char *)fifo->base + length);
}

static void shard_mmap_window(struct shard *shard)
{
	shard_mmap(shard, shard->head, shard->map->window);
}

static void shard_mmap_entire(struct shard *shard)
{
	shard_mmap(shard, 0, shard->fence);
}

static void shard_unmap(struct shard *shard)
{
	struct shard_fifo *fifo = &shard->fifo;
	if (munmap(fifo->base, fifo->top - fifo->base) == -1)
		errno_exit();
	fifo->base = fifo->tail = fifo->top = NULL;
}

struct shard_info { unsigned total, empty; };

static struct shard_info shard_dump(struct shard *shard, unsigned flags, const char *tag)
{
	if (flags & 1)
		printf("shard entries = %i size = %u, buckets = %u, used = %u\n",
			shard->size, shard->count, shard_buckets(shard), shard->used);
	unsigned count = 0, empty = 0;
	for (unsigned bucket = 0; bucket < shard_buckets(shard); bucket++) {
		if (!bucket_is_empty(shard, bucket)) {
			printf("%s%u ", tag, bucket);
			for (unsigned entry = bucket; ; entry = entry_next(shard, shard_entry(shard, entry))) {
				printf("%x@%u ",
					(bucket << shard->lowbits) + entry_key(shard, shard_entry(shard, entry)),
					entry_block(shard, shard_entry(shard, entry)));
				count++;
				if (entry_next(shard, shard_entry(shard, entry)) == endlist)
					break;
			}
			printf("\n");
		} else empty++;
	}
	if (flags & 1)
		printf("(%u entries, %u empty buckets)\n", count, empty);
	if (flags & 2) {
		if (shard->free) {
			printf("free entries:");
			for (unsigned link = shard->free; link; link = entry_next(shard, shard_entry(shard, link)))
				printf(" %u", link);
			printf("\n");
		}
	}
	assert(shard->count == count);
	return (struct shard_info){ count, empty };
}

static unsigned shard_probe(struct shard *shard, hashkey_t key, unsigned *next)
{
	if (0)
		printf("shard_probe 0x%Lx\n", key);
	unsigned bucket = key >> shard->lowbits, lowkey = key & shard->lowmask;

	assert(bucket < shard_buckets(shard));
	if (bucket_is_empty(shard, bucket))
		return -1;

	unsigned link = *next ? : bucket;
	do {
		struct shard_entry *entry = shard_entry(shard, link);
		if (0)
			hexdump(entry, sizeof *entry);
		if (0)
			printf("entry = %p (0x%x, %u)\n", entry, entry_key(shard, entry), entry_block(shard, entry));
		if (/*1 || */entry_key(shard, entry) == lowkey) {
			*next = entry_next(shard, entry);
			return entry_block(shard, entry);
		}
		link = entry_next(shard, entry);
	} while (link != endlist);

//	printf("not found\n");
	return -1;
}

static inline void entry_free(struct shard *shard, unsigned free) // embed me!
{
	assert(free >= shard_buckets(shard));
	if (0)
		printf("free 0x%x@%u\n",
			entry_key(shard, shard_entry(shard, free)),
			entry_block(shard, shard_entry(shard, free)));
	set_entry_next(shard, shard_entry(shard, free), shard->free);
	shard->free = free;
}

void fifo_advance(struct shard *shard) {
	if (filebacked) {
		shard_unmap(shard);
		shard->head += shard->map->window;
		assert(shard->head < shard->fence); // reshard goes here!
		if (0)
			printf("*** advance fifo %i window to %u of %u ***\n",
				shard_id(shard), shard->head, shard->fence);
		shard_mmap_window(shard);
	} else {
		struct shard_fifo *fifo = &shard->fifo;
		unsigned bytes = (char *)fifo->top - (char *)fifo->base, bigger = bytes * 2;
		if (1)
			printf("*** realloc fifo to %u ***\n", bigger);
		struct fifo_entry *big = realloc(fifo->base, bigger);
		assert(big);
		fifo->base = fifo->tail = big;
		fifo->top = (struct fifo_entry *)((char *)fifo->base + bigger);
	}
}

static void fifo_append(struct shard *shard, hashkey_t key, unsigned block, int insert)
{
	if (!filebacked)
		return;
	if (0 && shard->id == 0)
		printf("%Lx:%x ", key, block);
	if (0)
		printf("fifo_append %Lx at %x\n", key, fifo_tail(shard));
	if (0)
		printf("fifo %i used %tu of %tu window %Ld\n", shard_id(shard),
			(char *)shard->fifo.tail - (char *)shard->fifo.base,
			(char *)shard->fifo.top - (char *)shard->fifo.base,
			(s64)shard->map->window);
	assert(shard->fifo.tail < shard->fifo.top);
	set_fentry(shard->fifo.tail, block, insert, key);
	// block can be zero so block + 1 will be loaded into hash
	shard->fifo.tail++;
}

static int shard_insert_no_fifo(struct shard *shard, hashkey_t key, unsigned block)
{
	assert(!((block + 1) & ~shard->blockmask));
	unsigned bucket = key >> shard->lowbits, lowkey = key & shard->lowmask;
	assert(bucket < shard_buckets(shard));

	unsigned next = endlist;
	if (!bucket_is_empty(shard, bucket)) {
		if (shard->free) {
			unsigned free = shard->free;
			shard->free = entry_next(shard, shard_entry(shard, free));
			next = free;
		} else {
			//assert(shard->used < shard->size);
			if (shard->used == shard->size) {
				printf("Warning: out of entries in shard %d\n", shard->id);
				return 1;
			}
			next = shard->used++;
		}
	}

	if (next != endlist) {
		*shard_entry(shard, next) = *shard_entry(shard, bucket);
	}

	set_entry(shard, shard_entry(shard, bucket), lowkey, block, next);

	return 0;
}

static int shard_insert(struct shard *shard, unsigned key, unsigned block)
{
	if (0)
		printf("shard_insert 0x%x@%u\n", key, block);
	if (shard->fifo.tail == shard->fifo.top)
		fifo_advance(shard);
	shard_insert_no_fifo(shard, key, block);
	fifo_append(shard, key, block, 1);
	shard->count++;
	return 0;
}

static int shard_delete(struct shard *shard, unsigned key, unsigned block)
{
	if (0)
		printf("shard_delete key = %x, block = %i\n", key, block);
	unsigned bucket = key >> shard->lowbits, lowkey = key & shard->lowmask;
	assert(bucket < shard_buckets(shard));
	if (!bucket_is_empty(shard, bucket))
		for (struct shard_entry *entry = shard_entry(shard, bucket), *prev = NULL; 1; 
		     prev = entry, entry = shard_entry(shard, entry_next(shard, entry))) {
			if (0)
				printf("entry = %p {0x%x, %u}\n", entry, entry_key(shard, entry), entry_key(shard, entry));
			if (0)
				printf("next = %i\n", entry_next(shard, entry));
			if (entry_key(shard, entry) == lowkey && entry_block(shard, entry) == block) {
				unsigned kill;
				if (!prev) {
					kill = entry_next(shard, entry);
					if (kill == endlist) {
						set_entry(shard, entry, 0, 0, noentry);
						goto append;
					}
					*entry = *shard_entry(shard, kill);
				} else {
					kill = entry_next(shard, prev);
					set_entry_next(shard, prev, entry_next(shard, entry));
				}
				entry_free(shard, kill);
				goto append;
			}
			if (entry_next(shard, entry) == endlist)
				break;
		}
	printf("not found\n");
	return 1;
append:
	if (0)
		printf("fifo delete %x at %x\n", key, fifo_tail(shard));
	if (shard->fifo.tail == shard->fifo.top)
		fifo_advance(shard);
	fifo_append(shard, key, block, 0);
	shard->count--;
	return 0;
}

static struct shard *new_shard(unsigned size, unsigned fence, unsigned bucketbits, unsigned lowbits) {
	unsigned blockbits = keybits - lowbits;
	if (1)
		printf("new shard maxentries = %i, bucketbits = %i, fence = %u\n", size, bucketbits, fence);
	struct shard *shard = malloc(shard_bytes(size));
#ifdef PAGEVEC
	size = align(size * sizeof(struct shard_entry), PAGEBITS) / sizeof(struct shard_entry);
	shard_populate(shard, 0, (size * sizeof(struct shard_entry)) >> PAGEBITS);
#endif
	assert(shard);
	*shard = (struct shard){
		.size = size, .fence = fence, .bucketbits = bucketbits, .lowbits = lowbits,
		.lowmask = ~(-1 << lowbits), .blockbits = keybits - lowbits, .blockmask = (1LL << blockbits) - 1,
		.used = 1 << bucketbits };

	for (unsigned i = 0, buckets = shard_buckets(shard); i < buckets; i++)
		set_entry(shard, shard_entry(shard, i), 0, 0, noentry);
	return shard;
}

static struct shard *shard_rehash(struct shard *shard, unsigned newsize, unsigned factor)
{
	if (1)
		printf("*** rehash shard %i from %i to %i bucket bits (%u entries) ***\n",
			shard->id, shard->bucketbits, shard->bucketbits + factor, shard->count);
	struct shard *newshard = new_shard(newsize, shard->fence, shard->bucketbits + factor, shard->lowbits - factor);
	newshard->fifo = shard->fifo;
	newshard->id = shard->id;
	for (unsigned bucket = 0; bucket < shard_buckets(shard); bucket++) {
		if (!bucket_is_empty(shard, bucket)) {
			for (unsigned entry = bucket; ; entry = entry_next(shard, shard_entry(shard, entry))) {
				unsigned key = (bucket << shard->lowbits) | entry_key(shard, shard_entry(shard, entry));
				shard_insert(newshard, key, entry_block(shard, shard_entry(shard, entry)));
				if (entry_next(shard, shard_entry(shard, entry)) == endlist)
					break;
			}
		}
	}
if (0 && newshard->id == 58)
	BREAK;
	free(shard);
	return newshard;
}

/*
 * Shard table operations
 */

static unsigned map_shards(struct shardmap *map)
{
	return 1 << map->mapbits;
}

static void map_dump(struct shardmap *map)
{
	unsigned total = 0, empty = 0;
	printf("%i shards:\n", map_shards(map));
	char tag[10];
	for (unsigned i = 0; i < map_shards(map); i++) {
		struct shard *shard = map->table[i];
		if (!shard)
			continue;
		snprintf(tag, sizeof tag, "%i#", i);
		struct shard_info info = shard_dump(shard, 0, tag);
		total += info.total;
		empty += info.empty;
		if (0)
			printf("empty = %i\n", info.empty);
	}
	printf("entries = %i, empty = %i\n", total, empty);
}

void init_fifo(struct shard_fifo *fifo, struct fifo_entry *base, unsigned bytes)
{
	assert(fifo); // can easily fail with a large cache
	fifo->base = fifo->tail = base;
	fifo->top = (struct fifo_entry *)((char *)fifo->base + bytes);
}

static struct shard *map_populate(struct shardmap *map, unsigned i)
{
	assert(!map->table[i]);
	unsigned bucketbits = map->shardbits - map->lowbits;
	unsigned size = align(sizeof(struct fifo_entry) * (1 << (bucketbits + 1)), 12 - shard_entry_bits);
	assert(size <= 1 << map->fencebits); // wrong!!! size is in entries by fence is in bytes

	struct shard *shard = new_shard(size, 1 << map->fencebits, bucketbits, map->lowbits);
	map->table[i] = shard;
	shard->map = map;
	shard->id = i;

	return shard;
}

static void populate_and_map(struct shardmap *map, unsigned i)
{
	struct shard *shard = map_populate(map, i);

	if (filebacked)
		shard_mmap_window(shard);
	else
		init_fifo(&shard->fifo, malloc(shard->size), shard->size);

	if (0)
		for (unsigned i = 0; i < 1 << map->mapbits; i++)
			printf("shard %i: 0x%Lx\n", i, (long long)fifo_pos(map->table[i]));
}

static unsigned map_probe(struct shardmap *map, hashkey_t key, unsigned *next)
{
	assert(!(key & ~map_keymask(map)));
	unsigned i = key >> map->shardbits;
	if (!map->table[i])
		populate_and_map(map, i);
	return shard_probe(map->table[i], key & shard_keymask(map), next);
}

static int map_insert(struct shardmap *map, hashkey_t key, unsigned block)
{
	if (0)
		printf("insert 0x%Lx@%u\n", key, block);
	assert(!(key & ~map_keymask(map)));
	unsigned i = key >> map->shardbits;
	if (!map->table[i])
		populate_and_map(map, i);
	struct shard *shard = map->table[i];
	unsigned k = key & ~(-1 << map->shardbits);
	if (0)
		printf("map_insert shard = %Li, key = %x\n", key >> map->shardbits, k);
	if (0 && shard->count >= 16 << shard->bucketbits && shard->lowbits > 2)
		shard = map->table[i] = shard_rehash(shard, shard->size, 2);
	if (!shard_insert(shard, k, block))
		return 0;
	if (0)
		printf("*** realloc shard ***\n");
	unsigned newsize = shard->size * 2;
#ifdef PAGEVEC
	unsigned at = (shard->size * sizeof(struct shard_entry)) >> PAGEBITS;
	shard_populate(shard, at, (newsize * sizeof(struct shard_entry)) >> PAGEBITS);
#else
	struct shard *newshard = realloc(shard, shard_bytes(newsize));
	assert(newshard);
	int fail = shard_insert(shard = map->table[i] = newshard, k, block);
	assert(!fail);
#endif
	shard->size = newsize;
	return 0;
}

static int map_delete(struct shardmap *map, hashkey_t key, unsigned block)
{
	assert(!(key & ~map_keymask(map)));
	if (0)
		printf("map_delete shard = %Li, key = %Lx\n", key >> map->shardbits, key);
	unsigned i = key >> map->shardbits;
	if (!map->table[i])
		populate_and_map(map, i);
	return shard_delete(map->table[i], key & shard_keymask(map), block);
}

static struct shardmap *alloc_map(int fd, unsigned mapbits, unsigned shardbits, unsigned lowbits, u64 base) {
	enum {maxwindow = 1 << 13, fifo_entry_size_bits = 3 };
	unsigned shards = 1 << mapbits, mapmask = ~(-1 << mapbits);
	unsigned windowbits = 13, window = 1 << windowbits;
	unsigned fencebits = shardbits - lowbits + fifo_entry_size_bits + 3;

	if (fencebits < windowbits)
		fencebits = windowbits;

	if (1)
		printf("alloc shardmap keybits = %i, mapbits = %i, shardbits = %i\n",
			mapbits + shardbits, mapbits, shardbits);

	struct shardmap *map = malloc(sizeof(struct shardmap) + shards * sizeof(map->table[0]));
	*map = (struct shardmap){
		.mapbits = mapbits, .mapmask = mapmask, .shardbits = shardbits, .lowbits = lowbits, .fencebits = fencebits,
		.fd = fd, .base = base, .window = window };

	map->fifomap_size = align(shards * sizeof map->fifomap[0], blocksize_bits);
	map->tailmap_size = align(shards * sizeof map->tailmap[0], blocksize_bits);
	map->fifomap = malloc(map->fifomap_size);
	map->tailmap = malloc(map->tailmap_size);
	memset(map->table, 0, shards * sizeof map->table[0]);

	return map;
}

/*
 * Index delete normally appends a negative entry to the end of the fifo to
 * avoid reloading earlier fifo blocks. Later, the entire shard is loaded and
 * normalized to remove redundant create/delete pairs. The cache footprint for
 * normalize is thus a single shard. After normalize the shard is in sorted
 * order by key then block, though this fact is not used.
 */
static int normalize(struct shard_fifo *fifo, unsigned count)
{
	enum { trace = 0 };
	if (0)
		hexdump(fifo->base, count * sizeof fifo->base[0]);
	if (0)
		for (unsigned j = 0; j < count; j++)
			printf("%u: %c%x:%u\n", j, "-+"[fentry_is_insert(&fifo->base[j])], fentry_key(&fifo->base[j]), fentry_block(&fifo->base[j]));
	if (0)
		for (unsigned j = 0; j < count; j++) {
			if (fentry_is_insert(&fifo->base[j]))
				printf("inserted %u\n", j);
			else
				printf("deleted %u\n", j);
		}

	be_u64 *data = (be_u64 *)fifo->base;
	COMBSORT(count, I, J, data[I] < data[J], EXCHANGE(data[I], data[J]));
	if (0)
		printf("count = %u\n", count);
	if (0)
		for (unsigned j = 0; j < count; j++)
			printf("%u: %c%x:%u\n", j, "-+"[fentry_is_insert(&fifo->base[j])], fentry_key(&fifo->base[j]), fentry_block(&fifo->base[j]));

	struct fifo_entry *head = fifo->base, *tail = fifo->base, *top = fifo->base + count;
	be_u64 last = -1;

	unsigned balance = 0;

creates:
	if (tail == top)
		goto done;

	if (!fentry_is_insert(tail)) {
		last = fentry_block(tail);
		goto deletes;
	}

	if (trace)
		printf("create 1\n");
	*head++ = *tail++;
	goto creates;

deletes:
	// while delete bit, count deletes
	// fail if entry does not match 
	balance++;
	if (++tail == top)
		goto fail;

	if (fentry_block(tail) != last)
		goto fail;

	if (trace)
		printf("delete 1\n");
	if (fentry_is_insert(tail))
		goto cancels;

	goto deletes;

cancels:
	// while positive balance, remove creates
	// fail if entry does not match or no create bit
	if (trace)
		printf("cancel 1\n");
	if (!--balance)
		goto cancelled;

	if (++tail == top)
		goto fail;

	if (fentry_block(tail) != last)
		goto fail;

	goto cancels;

cancelled:
	tail++;
	goto creates;

done:
	if (trace)
		printf("done\n");
	if (0)
		printf("count = %tu\n", head - fifo->base);
	return head - fifo->base;

fail:
	printf("fail\n");
	return -1;
}

/*
 * Directory level operations
 */

enum { blockbits = 12, blocksize = 1 << blockbits, blockmask = blocksize - 1 };

struct dirent {
	be_u32 ino;
	/*be_u16 version;*/
	be_u8 len;
	u8 text[];
} __attribute__((packed));

struct dirhead {
	char magic[2]; be_u16 flags; u8 version[4]; be_u64 base:48, mapbits:8, shardbits:8;
	be_u64 current; // miserable excuse for a free record search accelerator
};

enum { default_lowbits = 6 };

static struct shardmap *dir_open(int fd)
{
	struct dirhead head;
	if (pread(fd, &head, sizeof head, 0) == -1)
		errno_exit();

	struct shardmap *map = alloc_map(fd, head.mapbits, head.shardbits, default_lowbits, head.base);
	if (pread(map->fd, map->fifomap, map->fifomap_size, map->base) == -1) // endian!!!
		errno_exit();
	if (pread(map->fd, map->tailmap, map->tailmap_size, map->base + map->fifomap_size) == -1)
		errno_exit();

	printf("map base = %Lx, shards = %i, shardbits = %i\n", (long long)head.base, map_shards(map), head.shardbits);

	for (unsigned i = 0; i < map_shards(map); i++) {
		unsigned count = map->tailmap[i]; // endian!!!
		if (0)
			printf("%i: count = %u\n", i, count);
		if (!count)
			continue;
		assert(!map->table[i]);
		map_populate(map, i);
		struct shard *shard = map->table[i];
		shard_mmap_entire(shard);
		struct shard_fifo *fifo = &shard->fifo;

		if (1 || i == 0) {
			int newcount = normalize(fifo, count);
			if (newcount >= 0)
				map->tailmap[i] = count = newcount;
		}

		for (unsigned j = 0; j < count; j++) {
			struct fifo_entry *entry = shard->fifo.base + j;
			if (0 && i == 0) {
				printf("%c%x:%x ", "-+"[fentry_is_insert(entry)], fentry_key(entry), fentry_block(entry));
				if (j % 10 == 9)
					printf("\n");
			}
			assert(fentry_is_insert(entry));
			if (fentry_is_insert(entry))
				shard_insert_no_fifo(shard, fentry_key(entry), fentry_block(entry));
			else
				shard_delete(shard, fentry_key(entry), fentry_block(entry));
		}
		if (0)
			printf("\n");
		shard_unmap(shard);
		shard_mmap_window(shard);
		unsigned tail = map->tailmap[i] * sizeof(struct fifo_entry); // endian!!!
		shard->head = tail & (-1 << blocksize_bits);
		shard->fifo.tail = (struct fifo_entry *)((char *)shard->fifo.base + (tail & ~(-1 << blocksize_bits)));
		if (0)
			printf("%i: tail = %x\n", i, fifo_tail(map->table[i]));
		if (0 && i == 0)
			shard_dump(shard, 1, "");
	}
	return map;
}

static void dir_save(struct shardmap *map)
{
	if (0)
		for (unsigned i = 0; i < map_shards(map); i++)
			printf("%i: tail = %x\n", i, fifo_tail(map->table[i]));

	for (unsigned i = 0; i < map_shards(map); i++) {
		struct shard *shard = map->table[i];
		if (!shard)
			continue;
		msync(shard->fifo.base, shard->fifo.tail - shard->fifo.base, MS_SYNC);
		map->tailmap[i] = fifo_tail(shard); // endian!!!
	}

	if (!filebacked)
		return;

	if (pwrite(map->fd, map->fifomap, map->fifomap_size, map->base) == -1) // endian!!!
		errno_exit();
	if (pwrite(map->fd, map->tailmap, map->tailmap_size, map->base + map->fifomap_size) == -1)
		errno_exit();
	if (pwrite(map->fd, (be_u64[]){lseek(map->fd, 0, SEEK_CUR)}, sizeof(be_u64), offsetof(struct dirhead, current)) == -1)
		errno_exit();
}

static loff_t dir_tail;
static void *mapped_ptr;
static unsigned mapped_block;

void *get_block(struct shardmap *map, unsigned block)
{
	loff_t offset = block << blockbits;

	if (mapped_ptr) {
		if (block == mapped_block)
			return mapped_ptr;

		if (munmap(mapped_ptr, blocksize) == -1)
			errno_exit();
	}

	mapped_ptr = mmap(NULL, blocksize, PROT_WRITE, MAP_SHARED, map->fd, offset);
	if (mapped_ptr == MAP_FAILED)
		errno_exit();

	mapped_block = block;
	return mapped_ptr;
}

static struct dirent *find_dirent(struct shardmap *map, unsigned block, const void *name, unsigned len)
{
	unsigned char *buffer = get_block(map, block);
	void *p = buffer, *top = buffer + blocksize;
	struct dirent *entry;

	assert(len <= UCHAR_MAX);
	if (block == 0)
		p += sizeof(struct dirhead);

	while (p + sizeof(*entry) + 1 < top) {
		entry = p;
		if ((void *)entry->text + entry->len > top) {
			assert(0); /* Out of range */
			return NULL;
		}

		/* Hole on end of block */
		if (!entry->text[0])
			break;

		if (len == entry->len && !memcmp(name, entry->text, len))
			return entry;

		p += sizeof(*entry) + entry->len;
	}

	return NULL;
}

static void entry_create(struct shardmap *map, char *name, unsigned len, unsigned ino) {
	hashkey_t keymask = map_keymask(map);
	hashkey_t key = siphash((unsigned char *)name, len) & keymask;
	unsigned bucket = key >> map->shardbits;

	if (!map->table[bucket])
		populate_and_map(map, bucket);

	struct shard *shard = map->table[bucket];

	for (unsigned i = 0, next = 0; i < 9999; i++) { // paranoia limit, should be entry could of shard or something
		unsigned block = shard_probe(shard, key & shard_keymask(map), &next);
		if (block == -1)
			break;
//		printf("search block %i\n", block);
		struct dirent *entry = find_dirent(map, block, name, len);
		if (entry) {
			errno = EEXIST;
			errno_exit();
		}
		if (!next)
			break;
	}

	// always append to last block just for now
	unsigned last_block = dir_tail >> blockbits;
	unsigned char *buffer = get_block(map, last_block);
	unsigned need = sizeof(struct dirent) + len;
	unsigned room = blocksize - (dir_tail - (last_block << blockbits));

	if (need > room) {
		if (0)
			printf("append block %i\n", last_block);
		last_block++;
		dir_tail = last_block << blockbits;
		buffer = get_block(map, last_block);
		memset(buffer, 0, blocksize);
	}

	struct dirent *entry = (struct dirent *)(buffer + (dir_tail & blockmask));
	*entry = (struct dirent){ .ino = ino, .len = len };
	memcpy(entry->text, name, len);
	dir_tail += need;
	map_insert(map, key, last_block);
	if (0)
		hexdump(buffer, 256);
}

static void entry_delete(struct shardmap *map, char *name, unsigned len) {
	hashkey_t keymask = map_keymask(map);
	hashkey_t key = siphash((unsigned char *)name, len) & keymask;
	unsigned bucket = key >> map->shardbits;
	if (0)
		printf("delete '%.*s'\n", len, name);

	if (!map->table[bucket])
		populate_and_map(map, bucket);

	struct shard *shard = map->table[bucket];

	for (unsigned i = 0, next = 0; i < 9999; i++) { // paranoia limit, should be entry could of shard or something
		unsigned block = shard_probe(shard, key & shard_keymask(map), &next);
		if (block == -1)
			break;
		if (0)
			printf("search block %i\n", block);
		struct dirent *entry = find_dirent(map, block, name, len);
		if (entry) {
			shard_delete(shard, key & shard_keymask(map), block);
			entry->text[0] = 0;
			return;
		}
		if (!next)
			break;
	}
	errno = ENOENT;
	errno_exit();
}

static unsigned entry_lookup(struct shardmap *map, char *name, unsigned len) {
	unsigned keymask = map_keymask(map);
	unsigned key = siphash((unsigned char *)name, len) & keymask;
	unsigned bucket = key >> map->shardbits;

	if (!map->table[bucket])
		populate_and_map(map, bucket);

	struct shard *shard = map->table[bucket];

	for (unsigned i = 0, next = 0; i < 9999; i++) { // paranoia limit, should be entry count of shard or something
		unsigned block = shard_probe(shard, key & ~(-1 << map->shardbits), &next);
		if (block == -1)
			break;
		if (0)
			printf("search block %i\n", block);
		struct dirent *entry = find_dirent(map, block, name, len);
		if (entry)
			return entry->ino;
		if (!next)
			break;
	}
	errno = ENOENT;
	errno_exit();
	return 0;
}

static struct shardmap *new_map(int fd, unsigned mapbits, unsigned shardbits, u64 base) {
	struct shardmap *map = alloc_map(fd, mapbits, shardbits, default_lowbits, base);
	unsigned map_head_size = map->fifomap_size + map->tailmap_size;
	loff_t stride = 1 << map->fencebits;

	if (1)
		printf("fifomap_size = 0x%x, tailmap_size = 0x%x, stride = %Li\n",
			map->fifomap_size, map->tailmap_size, (long long)stride);

	unsigned fifobase = map_head_size;

	for (unsigned i = 0; i < map_shards(map); i++, fifobase += stride) {
		if (0)
			printf("map shard %i, window %u\n", i, map->window);
		map->fifomap[i] = fifobase;
		map->tailmap[i] = 0;
	}

	if (filebacked) {
		if (1)
			printf("file size = 0x%Lx\n", (s64)(map->base + fifobase));
		struct dirhead head = { .magic = { 0xac, 0xdc }, .base = map->base, .mapbits = map->mapbits, .shardbits = map->shardbits };
		if (pwrite(fd, &head, sizeof head, 0) == -1)
			errno_exit();
		if (0)
			hexdump(&head, sizeof head);
		dir_tail = sizeof head;
		if (ftruncate(fd, map->base + fifobase))
			errno_exit();
	}

	return map;
}

static void map_free(struct shardmap *map) {
	if (0)
		printf("map_free shards = %i\n", map_shards(map));
	for (unsigned i = 0; i < map_shards(map); i++) {
		if (!filebacked && map->table[i])
			free(map->table[i]->fifo.base);
		free(map->table[i]);
	}
	free(map->fifomap);
	free(map->tailmap);
	free(map);
}

static void dir_free(struct shardmap *map) {
	map_free(map);
}

void test(void)
{
	if (0) {
		int fd = open("testdir", O_RDWR);
		if (fd == -1)
			errno_exit();

		struct shardmap *map = dir_open(fd);

		if (1)
			map_dump(map);

		dir_save(map);
		dir_free(map);
		return;
	}

	/* Insert test */
	if (1) {
		enum { big = 1 };
		enum { count = big ? 50000000 : 3000 };
		enum { mapbits = big ? 10 : 6, shardbits = (big ? 19 : 7) };

		int fd = open("testdir", O_CREAT | O_RDWR, 0644);
		if (fd == -1)
			errno_exit();

		struct shardmap *map = new_map(fd, mapbits, shardbits, 1ULL << 30);

		static struct timeval start, prev;
		gettimeofday(&start, NULL);
		prev = start;
		void progress(unsigned i) {
			static struct timeval tv, diff;
			gettimeofday(&tv, NULL);
			if (!(i % 100000)) {
				timersub(&tv, &start, &diff);
				fprintf(stderr, "%012u: %ld.%06ld\n", i, diff.tv_sec, diff.tv_usec);
				timersub(&tv, &prev, &diff);
				fprintf(stderr, "%ld.%06ld\n", diff.tv_sec, diff.tv_usec);
				prev = tv;
			}
		}

		for (unsigned i = 0; i < count; i++, progress(i)) {
			char name[10];
			int len;
			len = snprintf(name, sizeof(name), "%u", i);
			entry_create(map, name, len, i);
#if 0
			assert(entry_lookup(map, name, len) == i);
#endif
		}

		dir_save(map);
		dir_free(map);
		return;
	}

	/* Lookup test */
	if (0) {
		enum { big = 1 };
		enum { count = big ? 50000000 : 3000 };

		int fd = open("testdir", O_RDWR);
		if (fd == -1)
			errno_exit();

		struct shardmap *map = dir_open(fd);

		static struct timeval start, prev;
		gettimeofday(&start, NULL);
		prev = start;
		void progress(unsigned i) {
			static struct timeval tv, diff;

			gettimeofday(&tv, NULL);
			if (!(i % 100000)) {
				timersub(&tv, &start, &diff);
				fprintf(stderr, "%012u: %ld.%06ld\n", i, diff.tv_sec, diff.tv_usec);
				timersub(&tv, &prev, &diff);
				fprintf(stderr, "%ld.%06ld\n", diff.tv_sec, diff.tv_usec);
				prev = tv;
			}
		}

		for (unsigned i = 0; i < count; i++, progress(i)) {
			char name[10];
			int len;
			len = snprintf(name, sizeof(name), "%u", i);

			assert(entry_lookup(map, name, len) == i);
		}

		dir_free(map);
		return;
	}

	if (0) {
		enum { big = 1 };
		enum { count = big ? 1000000 : 3000 };
		enum { mapbits = big ? 10 : 6, shardbits = (big ? 19 : 7) };

		int fd = open("testdir", O_RDWR);
		if (fd == -1)
			errno_exit();

		struct shardmap *map = new_map(fd, mapbits, shardbits, 1ULL << 30);

		entry_create(map, "foo", 3, 0x123);
		unsigned ino = entry_lookup(map, "foo", 3);
		printf("ino = 0x%x\n", ino);

		if (1) {
			printf("---------\n");
			map_dump(map);
		}

		if (1)
			entry_delete(map, "foo", 3);

		if (1) {
			printf("---------\n");
			map_dump(map);
		}

		dir_save(map);
		dir_free(map);
		return;
	}

	if (0) {
		enum { big = 0, dirents = 1 };
		enum { count = big ? 1000000 : 30000 };
		enum { mapbits = big ? 10 : 5, shardbits = (big ? 19 : 7) };

		int fd = open("testdir", O_CREAT | O_RDWR, 0644);
		if (fd == -1)
			errno_exit();

		struct shardmap *map = new_map(fd, mapbits, shardbits, 1ULL << 30);

		void progress(unsigned i) {
			if (!(i % 1000000))
				fprintf(stderr, "\r%i", i);
		}

		if (0)
			return;

		static struct testitem { unsigned key, block; } testdata[count];

		enum { bufsize = 1 << blocksize_bits };
		static u8 buffer[bufsize], *tail = buffer + sizeof(struct dirhead), *top = buffer + bufsize;
		static unsigned block = 0;

		void flush_buffer(void) {
			memset(tail, 0, top - tail);
			if (write(fd, buffer, bufsize) == -1)
				errno_exit();
			tail = buffer;
		}

		struct dirhead head = { .magic = { 0xac, 0xdc },
			.base = map->base, .mapbits = map->mapbits, .shardbits = map->shardbits };

		memcpy(buffer, &head, sizeof head);

		hashkey_t keymask = map_keymask(map);
		for (unsigned j = 0; j < 2; j++) {
			fprintf(stderr, "%s...\n", j ? "deleting" : "inserting");
			for (unsigned i = 0; i < count >> (!j ? 0 : 1); i++, progress(i)) {
				if (!j) {
					struct { struct dirent head; char name[10]; } entry;
					entry.head.len = snprintf(entry.name, sizeof entry.name, "%u", i);
					unsigned use = sizeof entry.head + entry.head.len;
					hashkey_t key = siphash((unsigned char *)entry.name, entry.head.len) & keymask;

					if (use > top - tail) {
						flush_buffer();
						block++;
					}
					memcpy(tail, &entry, use);
					tail += use;

					map_insert(map, key, block);
					unsigned next = 0;
					if (1 && map_probe(map, key, &next) == -1) {
						printf("\n%i: missing 0x%Lx, keymask = %Lx\n", i, key, keymask);
						exit(0);
					}
					testdata[i] = (struct testitem){ key, block };
				} else {
					map_delete(map, testdata[i].key, testdata[i].block);
				}
			}
			printf("\n");
		}

		if (tail != buffer)
			flush_buffer();

		if (0)
			map_dump(map);

		dir_save(map);
		dir_free(map);
		return;
	}

	if (0 && !filebacked) {
		struct shardmap *map = new_map(0, 6, 8, 0);
		unsigned key = 0x311;
		map_insert(map, key, 1111);
		map_insert(map, key, 1111);
		map_dump(map);
		for (unsigned i = 0, next = 0; i < 100; i++) {
			unsigned found = map_probe(map, key, &next);
			printf("found = %i next = %i\n", found, next);
			if (!next)
				break;
		}
		map_delete(map, key, 1111);
		map_dump(map);
		return;
	}

	if (0 && !filebacked) {
		enum { big = 1 };
		enum { shardsize = 1 << (big ? 21 : 16), bucketbits = (big ? 15 : 4), lowbits = 6 };
		enum { count = big ? 1000 : 300 };
		static struct testitem { hashkey_t key, block; } testdata[count];
		hashkey_t keymask = ~(-1ULL << (bucketbits + lowbits));

		srand(1);
		for (unsigned i = 0; i < count; i++)
			testdata[i] = (struct testitem){ (rand() * rand()) & keymask, i + 1000 };

		unsigned window = count * 2;
		struct shard *shard = new_shard(shardsize, shardsize << 4, bucketbits, lowbits);
		init_fifo(&shard->fifo, malloc(window), window);

		for (unsigned i = 0; i < count; i++)
			shard_insert(shard, testdata[i].key, testdata[i].block);
		if (1) {
			shard_dump(shard, 0, "#");
			shard = shard_rehash(shard, shard->size * 2, 2);
			printf("---------\n");
			shard_dump(shard, 0, "#");
			if (0) {
				free(shard);
				return;
			}
			printf("---------\n");
		}
		for (unsigned i = 0; i < count; i++)
			shard_delete(shard, testdata[i].key, testdata[i].block);
		shard_dump(shard, 1, "#");
		if (1)
			return;
		for (unsigned i = 0; i < count; i++)
			shard_insert(shard, testdata[i].key, testdata[i].block);
		for (unsigned i = 0; i < count; i++)
			shard_delete(shard, testdata[i].key, testdata[i].block);
		shard_dump(shard, 3, "#");

		free(shard);
		return;
	}

	if (0 && !filebacked) {
		enum { shardsize = 1 << 8, bucketbits = 4, lowbits = 6 };
		struct shard *shard = new_shard(shardsize, shardsize << 4, bucketbits, lowbits);
		unsigned window = 6;
		init_fifo(&shard->fifo, malloc(window), window);

		shard_insert(shard, 0x111, 1111);
		shard_insert(shard, 0x122, 2222);
		shard_insert(shard, 0x133, 3333);
		shard_dump(shard, 3, "#");
		for (unsigned i = 0, next = 0; i < 100; i++) {
			unsigned found = shard_probe(shard, 0x111, &next);
			printf("found = %i next = %i\n", found, next);
			if (!next)
				break;
		}

		shard_delete(shard, 0x133, 3333);
		shard_delete(shard, 0x111, 1111);
		shard_delete(shard, 0x122, 2222);
		shard_dump(shard, 3, "#");
		free(shard);
		return;
	}

	if (0) {
		int i, n = 200, foo[n];
		srand(1);
		for (i = 0; i < n; i++)
			foo[i] = rand() % 100;
		printf("\n");
		printf("Random: "); for (i = 0; i < n; i++) printf ("%i ", foo[i]); 
		printf("\n");
		COMBSORT(n, I, J, foo[I] < foo[J], EXCHANGE(foo[I], foo[J]));
		printf("Sorted: "); for (i = 0; i < n; i++) printf ("%i ", foo[i]); 
		printf("\n");
		return;
	}
}

int main(int argc, const char *argv[]) {
	if (0) {
		errno = 28;
		errno_exit();
	}
	test();
	return 0;
}
