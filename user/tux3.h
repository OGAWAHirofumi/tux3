#ifndef TUX3_H
#define TUX3_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <byteswap.h>
#include <sys/time.h>
#include <time.h>
#include "err.h"
#include "trace.h"
#include "buffer.h"

#ifdef __CHECKER__
#define __force		__attribute__((force))
#define __bitwise__	__attribute__((bitwise))
#else
#define __force
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t le_u16;
typedef uint32_t le_u32;
typedef uint64_t le_u64;
typedef long long L; // widen for printf on 64 bit systems

#define PACKED __attribute__ ((packed))
#define fieldtype(compound, field) typeof(((compound *)NULL)->field)
#define vecset(d, v, n) memset((d), (v), (n) * sizeof(*(d)))
#define veccopy(d, s, n) memcpy((d), (s), (n) * sizeof(*(d)))
#define vecmove(d, s, n) memmove((d), (s), (n) * sizeof(*(d)))

typedef u64 fixed32; /* Tux3 time values */
typedef u32 millisecond_t;
typedef int64_t inum_t;
typedef u64 tuxkey_t;
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

typedef u16 __bitwise be_u16;
typedef u32 __bitwise be_u32;
typedef u64 __bitwise be_u64;

static inline u16 from_be_u16(be_u16 val)
{
	return bswap_16((__force u16)val);
}

static inline u32 from_be_u32(be_u32 val)
{
	return bswap_32((__force u32)val);
}

static inline u64 from_be_u64(be_u64 val)
{
	return bswap_64((__force u64)val);
}

static inline be_u16 to_be_u16(u16 val)
{
	return (__force be_u16)bswap_16(val);
}

static inline be_u32 to_be_u32(u32 val)
{
	return (__force be_u32)bswap_32(val);
}

static inline be_u64 to_be_u64(u64 val)
{
	return (__force be_u64)bswap_64(val);
}

static inline void *encode16(void *at, unsigned val)
{
	*(be_u16 *)at = to_be_u16(val);
	return at + sizeof(u16);
}

static inline void *encode32(void *at, unsigned val)
{
	*(be_u32 *)at = to_be_u32(val);
	return at + sizeof(u32);
}

static inline void *encode64(void *at, u64 val)
{
	*(be_u64 *)at = to_be_u64(val);
	return at + sizeof(u64);
}

static inline void *encode48(void *at, u64 val)
{
	at = encode16(at, val >> 32);
	return encode32(at, val);
}

static inline void *decode16(void *at, unsigned *val)
{
	*val = from_be_u16(*(be_u16 *)at);
	return at + sizeof(u16);
}

static inline void *decode32(void *at, unsigned *val)
{
	*val = from_be_u32(*(be_u32 *)at);
	return at + sizeof(u32);
}

static inline void *decode64(void *at, u64 *val)
{
	*val = from_be_u64(*(be_u64 *)at);
	return at + sizeof(u64);
}

static inline void *decode48(void *at, u64 *val)
{
	unsigned part1, part2;
	at = decode16(at, &part1);
	at = decode32(at, &part2);
	*val = (u64)part1 << 32 | part2;
	return at;
}

/* Tux3 disk format */
#define SB_MAGIC_SIZE	8
#define SB_MAGIC { 't', 'u', 'x', '3', 0xdd, 0x08, 0x09, 0x06 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 * 2008-09-06: Actual checking starts
 */

#define MAX_INODES_BITS 48
#define MAX_BLOCKS_BITS 48
#define MAX_FILESIZE_BITS 60
#define MAX_FILESIZE (1LL << MAX_FILESIZE_BITS)
#define MAX_EXTENT (1 << 6)
#define SB_LOC (1 << 12)
#define SB struct sb *sb

struct disktree { be_u64 depth:16, block:48; };

struct disksuper
{
	char magic[SB_MAGIC_SIZE];
	be_u64 birthdate;
	be_u64 flags;
	be_u64 iroot;
	be_u64 aroot;
	be_u16 blockbits;
	be_u16 unused1;
	be_u32 unused2;
	be_u64 volblocks, freeblocks, nextalloc;
	be_u32 freeatom, atomgen;
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
	struct btree itable;
	char bogopad[4096 - sizeof(struct disksuper)]; // point to super in buffer!!!
	struct map *devmap;
	struct buffer *rootbuf;
	struct inode *bitmap, *rootdir, *vtable, *atable;
	unsigned blocksize, blockbits, blockmask;
	block_t volblocks, freeblocks, nextalloc;
	unsigned entries_per_node, max_inodes_per_block;
	unsigned version, atomref_base, unatom_base;
	unsigned freeatom, atomgen;
};

struct inode {
	struct sb *sb;
	struct map *map;
	struct btree btree;
	inum_t inum;
	unsigned i_version, present;
	u64 i_size, i_mtime, i_ctime, i_atime;
	unsigned i_mode, i_uid, i_gid, i_links;
	struct xcache *xcache;
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
	void *(*leaf_resize)(BTREE, tuxkey_t key, vleaf *leaf, unsigned size);
	void (*leaf_dump)(BTREE, vleaf *leaf);
	unsigned (*leaf_need)(BTREE, vleaf *leaf);
	unsigned (*leaf_free)(BTREE, vleaf *leaf);
	int (*leaf_chop)(BTREE, tuxkey_t key, vleaf *leaf);
	void (*leaf_merge)(BTREE, vleaf *into, vleaf *from);
	block_t (*balloc)(SB);
	void (*bfree)(SB, block_t block);
};

/*
 * Tux3 times are 32.32 fixed point while time attributes are stored in 32.16
 * format, trading away some precision to compress time fields by two bytes
 * each.  It is not clear whether the saved space is worth the lower precision.
 */
#define TIME_ATTR_SHIFT 16

static inline fixed32 tuxtimeval(unsigned sec, unsigned usec)
{
	return ((u64)sec << 32) + ((u64)usec << 32) / 1000000;
}

static inline fixed32 tuxtime(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return tuxtimeval(now.tv_sec, now.tv_usec);
}

static inline unsigned billionths(fixed32 val)
{
	return ((((val & 0xffffffff) * 1000000) + 0x80000000) >> 32) * 1000;
}

static inline u32 high32(fixed32 val)
{
	return val >> 32;
}

struct iattr {
	u64 isize, mtime, ctime, atime;
	unsigned mode, uid, gid, links;
} iattrs;

void hexdump(void *data, unsigned size);
block_t balloc(SB);
void bfree(SB, block_t block);

enum atkind {
	MIN_ATTR = 6,
	MODE_OWNER_ATTR = 6,
	DATA_BTREE_ATTR = 7,
	CTIME_SIZE_ATTR = 8,
	LINK_COUNT_ATTR = 9,
	MTIME_ATTR = 10,
	IDATA_ATTR = 11,
	XATTR_ATTR = 12,
	MAX_ATTRS,
	VAR_ATTRS = IDATA_ATTR
};

enum atbit {
	MODE_OWNER_BIT = 1 << MODE_OWNER_ATTR,
	CTIME_SIZE_BIT = 1 << CTIME_SIZE_ATTR,
	DATA_BTREE_BIT = 1 << DATA_BTREE_ATTR,
	LINK_COUNT_BIT = 1 << LINK_COUNT_ATTR,
	MTIME_BIT = 1 << MTIME_ATTR,
	IDATA_BIT = 1 << IDATA_ATTR,
	XATTR_BIT = 1 << XATTR_ATTR,
};

unsigned atsize[MAX_ATTRS] = {
	[MODE_OWNER_ATTR] = 12,
	[CTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
	[MTIME_ATTR] = 6,
	[IDATA_ATTR] = 2,
	[XATTR_ATTR] = 4,
};

struct xattr { u16 atom, size; char body[]; } PACKED;
struct xcache { u16 size, maxsize; struct xattr xattrs[]; } PACKED;

static inline struct xattr *xcache_next(struct xattr *xattr)
{
	return (void *)xattr->body + xattr->size;
}

static inline struct xattr *xcache_limit(struct xcache *xcache)
{
	return (void *)xcache + xcache->size;
}

void *encode_kind(void *attrs, unsigned kind, unsigned version)
{
	return encode16(attrs, (kind << 12) | version);
}

#endif
