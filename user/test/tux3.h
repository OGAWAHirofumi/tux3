#ifndef TUX3_H
#define TUX3_H

#include <inttypes.h>
#include "trace.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t le_u16;
typedef uint32_t le_u32;
typedef uint64_t le_u64;

#define fieldtype(structure, field) typeof(((struct structure *)NULL)->field)
#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

typedef u32 millisecond_t;
typedef int64_t block_t;
typedef int64_t inum_t;
typedef u64 tuxkey_t;
typedef u32 mode_t;
typedef int fd_t;

static inline int get_bit(unsigned char *bitmap, unsigned bit)
{
	return bitmap[bit >> 3] & (1 << (bit & 7));
}

static inline void set_bit(unsigned char *bitmap, unsigned bit)
{
	bitmap[bit >> 3] |= 1 << (bit & 7);
}

static inline void reset_bit(unsigned char *bitmap, unsigned bit)
{
	bitmap[bit >> 3] &= ~(1 << (bit & 7));
}

struct bleaf
{
	le_u16 magic, version;
	le_u32 count;
	le_u64 using_mask;
	struct etree_map { le_u32 offset; le_u32 block; } map[];
};

#define SB struct sb *sb
#define SB_MAGIC { 't', 'e', 's', 't', 0xdd, 0x08, 0x08, 0x06 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 */

struct btree { u64 index; u16 levels, pad[3]; };

struct superblock
{
	typeof((char[])SB_MAGIC) magic;
	u64 create_time;
	struct btree iroot;
	struct btree froot;
	struct btree aroot;
	u64 flags;
	u32 levels;
	u32 sequence; /* commit block sequence number */
	block_t blocks;
	u64 bitblocks;
	u32 blockbits;
};

struct sb
{
	struct superblock image;
	char bogopad[4096 - sizeof(struct superblock)];
	struct map *devmap;
	u32 alloc_per_node;
	struct buffer *rootbuf;
	struct inode *bitmap;
	unsigned blocksize;
	block_t freeblocks;
	block_t nextalloc;
};

struct inode {
	struct sb *sb;
	struct map *map;
	struct btree root;
	inum_t inum;
	u64 i_size, i_ctime, i_mtime, i_atime;
	mode_t i_mode;
	unsigned i_version;
};

struct file {
	struct inode *f_inode;
	unsigned f_version;
	loff_t f_pos;
};

struct dleaf;

struct btree_ops {
	int (*leaf_sniff)(SB, void *leaf);
	int (*leaf_init)(SB, void *leaf);
	tuxkey_t (*leaf_split)(SB, void *base, void *base2, int fudge);
	void *(*leaf_expand)(SB, void *base, inum_t inum, unsigned more);
	void (*leaf_dump)(SB, struct dleaf *leaf);
	unsigned (*leaf_need)(SB, struct dleaf *leaf);
	unsigned (*leaf_free)(SB, struct dleaf *leaf);
	void (*leaf_merge)(SB, struct dleaf *leaf, struct dleaf *from);
	block_t (*balloc)(SB);
};

void hexdump(void *data, unsigned size);
block_t balloc(SB);

#endif
