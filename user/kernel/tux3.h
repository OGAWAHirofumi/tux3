#ifndef TUX3_H
#define TUX3_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#define printf printk
#define vprintf vprintk
typedef loff_t block_t;

#include "trace.h"
#endif

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

/* Endian support */

typedef u16 __bitwise be_u16;
typedef u32 __bitwise be_u32;
typedef u64 __bitwise be_u64;

#ifdef __KERNEL__
static inline u16 from_be_u16(be_u16 val)
{
	return __be16_to_cpu(val);
}

static inline u32 from_be_u32(be_u32 val)
{
	return __be32_to_cpu(val);
}

static inline u64 from_be_u64(be_u64 val)
{
	return __be64_to_cpu(val);
}

static inline be_u16 to_be_u16(u16 val)
{
	return __cpu_to_be16(val);
}

static inline be_u32 to_be_u32(u32 val)
{
	return __cpu_to_be32(val);
}

static inline be_u64 to_be_u64(u64 val)
{
	return __cpu_to_be64(val);
}
#else
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
#endif

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

#ifdef __KERNEL__
typedef struct address_space map_t;

static inline map_t *mapping(struct inode *inode)
{
	return inode->i_mapping;
}
#endif

struct tux_path { struct buffer_head *buffer; struct index_entry *next; };

struct sb
{
	struct disksuper super;
	struct btree itable;
	char bogopad[4096 - sizeof(struct disksuper)]; // point to super in buffer!!!
	map_t *devmap;
	struct buffer_head *rootbuf;
	struct inode *bitmap, *rootdir, *vtable, *atable;
	unsigned blocksize, blockbits, blockmask;
	block_t volblocks, freeblocks, nextalloc;
	unsigned entries_per_node, max_inodes_per_block;
	unsigned version, atomref_base, unatom_base;
	unsigned freeatom, atomgen;
};

#ifdef __KERNEL__
struct tux_inode {
	struct sb *sb;
	struct map *map;
	struct btree btree;
	inum_t inum;
	unsigned i_version, present;
	u64 i_size, i_mtime, i_ctime, i_atime;
	unsigned i_mode, i_uid, i_gid, i_links;
	struct xcache *xcache;

	struct inode vfs_inode;
};

static inline struct tux_inode *tux_inode(struct inode *inode)
{
	return container_of(inode, struct tux_inode, vfs_inode);
}
#else
struct inode {
	struct sb *i_sb;
	map_t *map;
	struct btree btree;
	inum_t inum;
	unsigned i_version, present;
	u64 i_size;
	struct timespec i_mtime, i_ctime, i_atime;
	unsigned i_mode, i_uid, i_gid, i_nlink;
	struct xcache *xcache;
};

struct file {
	struct inode *f_inode;
	unsigned f_version;
	loff_t f_pos;
};

static inline map_t *mapping(struct inode *inode)
{
	return inode->map;
}

static inline struct sb *tux_sb(struct sb *sb)
{
	return sb;
}

static inline struct inode *tux_inode(struct inode *inode)
{
	return inode;
}
#endif /* !__KERNEL__ */

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

static inline u32 high32(fixed32 val)
{
	return val >> 32;
}

static inline unsigned billionths(fixed32 val)
{
	return (((val & 0xffffffff) * 1000000000ULL) + 0x80000000) >> 32;
}

static inline struct timespec spectime(fixed32 time)
{
	return (struct timespec){ .tv_sec = high32(time), .tv_nsec = billionths(time) };
}

static inline fixed32 tuxtime(struct timespec time)
{
	return ((u64)time.tv_sec << 32) + ((u64)time.tv_nsec << 32) / 1000000000ULL;
}

static inline struct timespec gettime(void)
{
#ifdef __KERNEL__
	return current_kernel_time();
#else
	struct timeval now;
	gettimeofday(&now, NULL);
	return (struct timespec){ .tv_sec = now.tv_sec, .tv_nsec = now.tv_usec * 1000 };
#endif
}

struct tux_iattr {
	u64 isize;
	struct timespec mtime, ctime, atime;
	unsigned mode, uid, gid, links;
};

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

extern unsigned atsize[MAX_ATTRS];

struct xattr { u16 atom, size; char body[]; };
struct xcache { u16 size, maxsize; struct xattr xattrs[]; };

static inline struct xattr *xcache_next(struct xattr *xattr)
{
	return (void *)xattr->body + xattr->size;
}

static inline struct xattr *xcache_limit(struct xcache *xcache)
{
	return (void *)xcache + xcache->size;
}

static inline void *encode_kind(void *attrs, unsigned kind, unsigned version)
{
	return encode16(attrs, (kind << 12) | version);
}

#ifdef __KERNEL__
struct inode *tux3_get_inode(struct super_block *sb, int mode, dev_t dev);

static inline void *bufdata(struct buffer_head *buffer)
{
	return buffer->b_data;
}

static inline size_t bufsize(struct buffer_head *buffer)
{
	return buffer->b_size;
}

static inline block_t bufindex(struct buffer_head *buffer)
{
	return buffer->b_blocknr;
}

static inline int bufcount(struct buffer_head *buffer)
{
	return atomic_read(&buffer->b_count);
}

#define bufmap(map) NULL // just ignore this until we have peekblk

static inline struct inode *buffer_inode(struct buffer_head *buffer)
{
	return buffer->b_page->mapping->host;
}

#else

static inline struct inode *buffer_inode(struct buffer_head *buffer)
{
	return buffer->map->inode;
}
#endif

#endif
