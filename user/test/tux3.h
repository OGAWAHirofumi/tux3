#ifndef TUX3_H
#define TUX3_H

#include <inttypes.h>
#include <byteswap.h>
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

/* Bitmaps */

// !!! change to bit zero at high end of byte, consistent with big endian !!! //
// Careful about bitops on kernel port - need to reverse on le arch, maybe some be too.

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

/* Endian support */

typedef u16 be_u16;
typedef u32 be_u32;
typedef u64 be_u64;

static inline u16 be_to_u16(be_u16 val)
{
	return bswap_16(val);
}

static inline u32 be_to_u32(be_u32 val)
{
	return bswap_32(val);
}

static inline u64 be_to_u64(be_u64 val)
{
	return bswap_64(val);
}

static inline be_u16 u16_to_be(u16 val)
{
	return bswap_16(val);
}

static inline be_u32 u32_to_be(u32 val)
{
	return bswap_32(val);
}

static inline be_u64 u64_to_be(u64 val)
{
	return bswap_64(val);
}

/* Tux3 disk format */

#define SB struct sb *sb
#define SB_MAGIC { 't', 'e', 's', 't', 0xdd, 0x08, 0x08, 0x06 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 */


#define MAX_INODES_BITS 48
#define MAX_BLOCKS_BITS 48
#define MAX_FILESIZE_BITS 60

struct disktree { be_u64 depth:16, block:48; };

struct disksuper
{
	typeof((char[])SB_MAGIC) magic;
	struct disktree itree;
	struct disktree ftree;
	struct disktree atree;
	u64 create_time;
	u64 flags;
	u32 levels;
	u32 sequence; /* commit block sequence number */
	block_t blocks;
	u64 bitblocks;
	u32 blockbits;
};

struct root { u64 depth:16, block:48; };

struct btree {
	struct sb *sb;
	struct btree_ops *ops;
	struct root root;
	u16 entries_per_leaf;
};

struct sb
{
	struct disksuper super;
	struct btree itree;
	struct btree ftree;
	struct btree atree;
	char bogopad[4096 - sizeof(struct disksuper)]; // point to super in buffer!!!
	struct map *devmap;
	struct buffer *rootbuf;
	struct inode *bitmap;
	unsigned blocksize, blockbits, blockmask;
	block_t freeblocks, nextalloc;
	unsigned entries_per_node, max_inodes_per_block;
	unsigned version;
};

struct inode {
	struct sb *sb;
	struct map *map;
	struct btree btree;
	inum_t inum;
	mode_t i_mode;
	u64 i_size, i_ctime, i_mtime, i_atime, i_uid, i_gid;
	unsigned i_version, i_links;
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
	tuxkey_t (*leaf_split)(BTREE, tuxkey_t key, vleaf *from, vleaf *into);
	void *(*leaf_expand)(BTREE, tuxkey_t key, vleaf *leaf, unsigned more);
	void (*leaf_dump)(BTREE, vleaf *leaf);
	unsigned (*leaf_need)(BTREE, vleaf *leaf);
	unsigned (*leaf_free)(BTREE, vleaf *leaf);
	void (*leaf_merge)(BTREE, vleaf *into, vleaf *from);
	block_t (*balloc)(SB);
};

struct iattr {
	unsigned present;
	struct root root;
	u64 mtime, ctime, atime, isize;
	u32 mode, uid, gid, links;
} iattrs;

void hexdump(void *data, unsigned size);
block_t balloc(SB);

#endif
