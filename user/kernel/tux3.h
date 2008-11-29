#ifndef TUX3_H
#define TUX3_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

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
typedef u64 inum_t;
typedef u64 tuxkey_t;

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

/* Special inode numbers */
#define TUX_BITMAP_INO		0
#define TUX_VTABLE_INO		2
#define TUX_ATABLE_INO		10
#define TUX_ROOTDIR_INO		13

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

struct cursor { struct buffer_head *buffer; struct index_entry *next; };

struct sb {
	struct disksuper super;

	struct btree itable;
	struct buffer_head *rootbuf;
	struct inode *bitmap, *rootdir, *vtable, *atable;
	unsigned blocksize, blockbits, blockmask;
	block_t volblocks, freeblocks, nextalloc;
	unsigned entries_per_node, max_inodes_per_block;
	unsigned version, atomref_base, unatom_base;
	unsigned freeatom, atomgen;
#ifdef __KERNEL__
	struct super_block *vfs_sb;
#else
	map_t *devmap;
#endif
};

#ifdef __KERNEL__
typedef struct {
	struct btree btree;
	inum_t inum;
	unsigned present;
	struct xcache *xcache;
	struct inode vfs_inode;
} tuxnode_t;

static inline struct sb *tux_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct super_block *vfs_sb(struct sb *sb)
{
	return sb->vfs_sb;
}

static inline tuxnode_t *tux_inode(struct inode *inode)
{
	return container_of(inode, tuxnode_t, vfs_inode);
}

typedef struct address_space map_t;

static inline map_t *mapping(struct inode *inode)
{
	return inode->i_mapping;
}

static inline void *malloc(size_t size)
{
	might_sleep();
	return kmalloc(size, GFP_NOFS);
}

static inline void free(void *ptr)
{
	kfree(ptr);
}
#else
typedef struct inode {
	struct btree btree;
	inum_t inum;
	unsigned present;
	struct xcache *xcache;
	struct sb *i_sb;
	map_t *map;
	u64 i_size;
	unsigned i_version;
	struct timespec i_mtime, i_ctime, i_atime;
	unsigned i_mode, i_uid, i_gid, i_nlink;
} tuxnode_t;

struct file {
	struct inode *f_inode;
	unsigned f_version;
	loff_t f_pos;
};

static inline struct sb *tux_sb(struct sb *sb)
{
	return sb;
}

static inline struct sb *vfs_sb(struct sb *sb)
{
	return sb;
}

static inline struct inode *tux_inode(struct inode *inode)
{
	return inode;
}

static inline map_t *mapping(struct inode *inode)
{
	return inode->map;
}
#endif /* !__KERNEL__ */

#define TUX_NAME_LEN 255

/* directory entry */
typedef struct {
	be_u32 inum;
	be_u16 rec_len;
	u8 name_len, type;
	char name[];
} tux_dirent;

/* version:10, count:6, block:48 */
struct diskextent { be_u64 block_count_version; };
/* count:8, keyhi:24 */
struct group { be_u32 count_and_keyhi; };
/* limit:8, keylo:24 */
struct entry { be_u32 limit_and_keylo; };
struct dleaf { be_u16 magic, groups, free, used; struct diskextent table[]; };

struct dwalk {
	struct dleaf *leaf;
	struct group *group, *gstop, *gdict;
	struct entry *entry, *estop;
	struct diskextent *exbase, *extent, *exstop;
	struct {
		struct group group;
		struct entry entry;
		int used, free, groups;
	} mock;
};

/* group wrappers */

static inline struct group make_group(tuxkey_t keyhi, unsigned count)
{
	return (struct group){ to_be_u32(keyhi | (count << 24)) };
}

static inline unsigned group_keyhi(struct group *group)
{
	return from_be_u32(*(be_u32 *)group) & 0xffffff;
}

static inline unsigned group_count(struct group *group)
{
	return *(unsigned char *)group;
}

static inline void set_group_count(struct group *group, int n)
{
	*(unsigned char *)group = n;
}

static inline void inc_group_count(struct group *group, int n)
{
	*(unsigned char *)group += n;
}

/* entry wrappers */

static inline struct entry make_entry(tuxkey_t keylo, unsigned limit)
{
	return (struct entry){ to_be_u32(keylo | (limit << 24)) };
}

static inline unsigned entry_keylo(struct entry *entry)
{
	return from_be_u32(*(be_u32 *)entry) & ~(-1 << 24);
}

static inline unsigned entry_limit(struct entry *entry)
{
	return *(unsigned char *)entry;
}

static inline void inc_entry_limit(struct entry *entry, int n)
{
	*(unsigned char *)entry += n;
}

/* extent wrappers */

static inline struct diskextent make_extent(block_t block, unsigned count)
{
	assert(block < (1ULL << 48) && count - 1 < (1 << 6));
	return (struct diskextent){ to_be_u64(((u64)(count - 1) << 48) | block) };
}

static inline unsigned extent_block(struct diskextent extent)
{
	return from_be_u64(*(be_u64 *)&extent) & ~(-1LL << 48);
}

static inline unsigned extent_count(struct diskextent extent)
{
	return ((from_be_u64(*(be_u64 *)&extent) >> 48) & 0x3f) + 1;
}

static inline unsigned extent_version(struct diskextent extent)
{
	return from_be_u64(*(be_u64 *)&extent) >> 54;
}

/* helper to get the index for extent in group/entry  */
static inline tuxkey_t get_index(struct group *group, struct entry *entry)
{
	return ((tuxkey_t)group_keyhi(group) << 24) | entry_keylo(entry);
}

/* dleaf wrappers */

static inline unsigned dleaf_groups(struct dleaf *leaf)
{
	return from_be_u16(leaf->groups);
}

static inline void set_dleaf_groups(struct dleaf *leaf, int n)
{
	leaf->groups = to_be_u16(n);
}

static inline void inc_dleaf_groups(struct dleaf *leaf, int n)
{
	leaf->groups = to_be_u16(from_be_u16(leaf->groups) + n);
}

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
	return (((val & 0xffffffff) * 1000000000) + 0x80000000) >> 32;
}

static inline struct timespec spectime(fixed32 time)
{
	return (struct timespec){ .tv_sec = high32(time), .tv_nsec = billionths(time) };
}

static inline fixed32 tuxtime(struct timespec time)
{
	return ((u64)time.tv_sec << 32) + ((u64)time.tv_nsec << 32) / 1000000000;
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

#ifndef ENOATTR
#define ENOATTR ENOENT
#endif

#ifndef XATTR_CREATE
#define XATTR_CREATE 1 // fail if xattr already exists
#define XATTR_REPLACE 2 // fail if xattr does not exist
#endif

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

struct ileaf;
static inline struct ileaf *to_ileaf(vleaf *leaf)
{
	return leaf;
}

/* for tree_chop */
struct delete_info {
	tuxkey_t key;
	block_t blocks, freed;
	block_t resume;
	int create;
};

#ifdef __KERNEL__
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

/* balloc.c */
block_t balloc_extent(SB, unsigned blocks);

/* btree.c */
void release_cursor(struct cursor cursor[], int depth);
struct cursor *alloc_cursor(int);
void free_cursor(struct cursor cursor[]);
int probe(BTREE, tuxkey_t key, struct cursor cursor[]);
int advance(BTREE, struct cursor cursor[]);
tuxkey_t next_key(struct cursor cursor[], int depth);
void show_tree_range(BTREE, tuxkey_t start, unsigned count);
int tree_chop(BTREE, struct delete_info *info, millisecond_t deadline);
int btree_leaf_split(struct btree *btree, struct cursor cursor[], tuxkey_t key);
void *tree_expand(struct btree *btree, tuxkey_t key, unsigned newsize, struct cursor cursor[]);
struct btree new_btree(SB, struct btree_ops *ops);

/* dir.c */
loff_t tux_create_entry(struct inode *dir, const char *name, int len, inum_t inum, unsigned mode);
tux_dirent *tux_find_entry(struct inode *dir, const char *name, int len, struct buffer_head **result);
int tux_delete_entry(struct buffer_head *buffer, tux_dirent *entry);
extern const struct file_operations tux_dir_fops;
extern const struct inode_operations tux_dir_iops;

/* dtree.c */
unsigned dleaf_free(BTREE, vleaf *leaf);
void dleaf_dump(BTREE, vleaf *vleaf);
extern struct btree_ops dtree_ops;
int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key);
tuxkey_t dwalk_index(struct dwalk *walk);
struct diskextent *dwalk_next(struct dwalk *walk);
void dwalk_back(struct dwalk *walk);
void dwalk_chop_after(struct dwalk *walk);
int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct diskextent extent);
int dwalk_pack(struct dwalk *walk, tuxkey_t index, struct diskextent extent);

/* filemap.c */
extern const struct address_space_operations tux_aops;
extern const struct address_space_operations tux_blk_aops;

/* iattr.c */
unsigned encode_asize(unsigned bits);
void dump_attrs(struct inode *inode);
void *encode_attrs(struct inode *inode, void *attrs, unsigned size);
void *decode_attrs(struct inode *inode, void *attrs, unsigned size);

/* ileaf.c */
void *ileaf_lookup(BTREE, inum_t inum, struct ileaf *leaf, unsigned *result);
inum_t find_empty_inode(BTREE, struct ileaf *leaf, inum_t goal);
int ileaf_purge(BTREE, inum_t inum, struct ileaf *leaf);
extern struct btree_ops itable_ops;

/* inode.c */
void tux3_clear_inode(struct inode *inode);
int tux3_write_inode(struct inode *inode, int do_sync);
struct inode *tux_create_inode(struct inode *dir, int mode);
struct inode *tux3_iget(struct super_block *sb, inum_t inum);

/* xattr.c */
int xcache_dump(struct inode *inode);
struct xcache *new_xcache(unsigned maxsize);
struct xattr *get_xattr(struct inode *inode, char *name, unsigned len);
int set_xattr(struct inode *inode, char *name, unsigned len, void *data, unsigned size, unsigned flags);
void *encode_xattrs(struct inode *inode, void *attrs, unsigned size);
unsigned decode_xsize(struct inode *inode, void *attrs, unsigned size);
unsigned encode_xsize(struct inode *inode);

/* temporary hack for buffer */
struct buffer_head *blockread(struct address_space *mapping, block_t iblock);
struct buffer_head *blockget(struct address_space *mapping, block_t iblock);

static inline int buffer_empty(struct buffer_head *buffer)
{
	return 1;
}

static inline struct buffer_head *set_buffer_empty(struct buffer_head *buffer)
{
	return buffer;
}

static inline void brelse_dirty(struct buffer_head *buffer)
{
	mark_buffer_dirty(buffer);
	brelse(buffer);
}
#else /* !__KERNEL__ */
static inline struct inode *buffer_inode(struct buffer_head *buffer)
{
	return buffer->map->inode;
}
#endif /* !__KERNEL__ */

#endif
