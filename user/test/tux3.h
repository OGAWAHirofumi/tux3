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
typedef long long L; // widen for printf on 64 bit systems

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

#define SB struct sb *sb
#define SB_MAGIC { 't', 'e', 's', 't', 0xdd, 0x08, 0x08, 0x06 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 */


#define MAX_INODES (1ULL << 48)

struct diskroot { u64 block:48, levels:8, unused:8; };

struct btree {
	struct sb *sb;
	struct btree_ops *ops;
	struct diskroot root;
	u16 entries_per_leaf;
};

struct superblock
{
	typeof((char[])SB_MAGIC) magic;
	struct diskroot itree;
	struct diskroot ftree;
	struct diskroot atree;
	u64 create_time;
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
	struct btree itree;
	struct btree ftree;
	struct btree atree;
	char bogopad[4096 - sizeof(struct superblock)];
	struct map *devmap;
	struct buffer *rootbuf;
	struct inode *bitmap;
	unsigned blocksize;
	block_t freeblocks;
	block_t nextalloc;
	unsigned entries_per_node, max_inodes_per_block;
};

struct inode {
	struct sb *sb;
	struct map *map;
	struct btree btree;
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

typedef void vleaf;

#define BTREE struct btree *btree

struct btree_ops {
	int (*leaf_sniff)(BTREE, vleaf *leaf);
	int (*leaf_init)(BTREE, vleaf *leaf);
	tuxkey_t (*leaf_split)(BTREE, vleaf *from, vleaf *into, tuxkey_t key);
	void *(*leaf_expand)(BTREE, vleaf *leaf, tuxkey_t key, unsigned more);
	void (*leaf_dump)(BTREE, vleaf *leaf);
	unsigned (*leaf_need)(BTREE, vleaf *leaf);
	unsigned (*leaf_free)(BTREE, vleaf *leaf);
	void (*leaf_merge)(BTREE, vleaf *into, vleaf *from);
	block_t (*balloc)(SB);
};

void hexdump(void *data, unsigned size);
block_t balloc(SB);

#endif
