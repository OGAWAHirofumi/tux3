#ifndef TUX3_H
#define TUX3_H

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/mutex.h>

typedef loff_t block_t;

#define printf printk
#define vprintf vprintk
#define die(code) BUG_ON(1)

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

#ifdef __KERNEL__
/* Endian support */
typedef __be16	be_u16;
typedef __be32	be_u32;
typedef __be64	be_u64;

static inline u16 from_be_u16(be_u16 val)
{
	return be16_to_cpu(val);
}

static inline u32 from_be_u32(be_u32 val)
{
	return be32_to_cpu(val);
}

static inline u64 from_be_u64(be_u64 val)
{
	return be64_to_cpu(val);
}

static inline be_u16 to_be_u16(u16 val)
{
	return cpu_to_be16(val);
}

static inline be_u32 to_be_u32(u32 val)
{
	return cpu_to_be32(val);
}

static inline be_u64 to_be_u64(u64 val)
{
	return cpu_to_be64(val);
}
#endif /* !__KERNEL__ */

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
#define SB_MAGIC_SIZE 8
#define SB_MAGIC { 't', 'u', 'x', '3', 0xdd, 0x08, 0x12, 0x12 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 * 2008-09-06: Actual checking starts
 * 2008-12-12: Atom dictionary size in disksuper instead of atable->i_size
 */

#define MAX_INODES_BITS 48
#define MAX_BLOCKS_BITS 48
#define MAX_FILESIZE_BITS 60
#define MAX_FILESIZE (1LL << MAX_FILESIZE_BITS)
#define MAX_EXTENT (1 << 6)
#define SB_LOC (1 << 12)

/* Special inode numbers */
#define TUX_BITMAP_INO		0
#define TUX_INVALID_INO		1
#define TUX_VTABLE_INO		2
#define TUX_ATABLE_INO		10
#define TUX_ROOTDIR_INO		13

struct disksuper
{
	/* Update magic on any incompatible format change */
	char magic[SB_MAGIC_SIZE];
	be_u64 birthdate;	/* Volume creation date */
	be_u64 flags;		/* Need to assign some flags */
	be_u64 iroot;		/* Root of the inode table btree */
	be_u64 aroot;		/* The atime table is a file now, delete on next format rev */
	be_u16 blockbits;	/* Shift to get volume block size */
	be_u16 unused1;		/* Throw away on next format rev */
	be_u32 unused2;		/* Throw away on next format rev */
	be_u64 volblocks;	/* Volume size */
	/* The rest should be moved to a "metablock" that is updated frequently */
	be_u64 freeblocks;	/* Should match total of zero bits in allocation bitmap */
	be_u64 nextalloc;	/* Get rid of this when we have a real allocation policy */
	be_u32 freeatom;	/* Beginning of persistent free atom list in atable */
	be_u32 atomgen;		/* Next atom number if there are no free atoms */
	be_u64 dictsize;	/* Size of the atom dictionary instead if i_size */
};

struct root {
	unsigned depth; /* btree levels not including leaf level */
	block_t block; /* disk location of btree root */
};

struct btree {
	struct rw_semaphore lock;
	struct sb *sb;		/* Convenience to reduce parameter list size */
	struct btree_ops *ops;	/* Generic btree low level operations */
	struct root root;	/* Cached description of btree root */
	u16 entries_per_leaf;	/* Used in btree leaf splitting */
};

/* Define layout of btree root on disk, endian conversion is elsewhere. */

static inline u64 pack_root(struct root *root)
{
	return (u64)root->depth << 48 | root->block;
}

static inline struct root unpack_root(u64 v)
{
	return (struct root){ .depth = v >> 48, .block = v & (-1ULL >> 16), };
}

/* Path cursor for btree traversal */

struct cursor {
	struct btree *btree;
#define CURSOR_DEBUG
#ifdef CURSOR_DEBUG
#define FREE_BUFFER	((void *)0xdbc06505)
#define FREE_NEXT	((void *)0xdbc06507)
	int maxlen;
#endif
	int len;
	struct path_level {
		struct buffer_head *buffer;
		struct index_entry *next;
	} path[];
};

/* Tux3-specific sb is a handle for the entire volume state */

struct sb {
	struct disksuper super;
	struct btree itable;	/* Cached root of the inode table */
	struct inode *bitmap;	/* allocation bitmap special file */
	struct inode *rootdir;	/* root directory special file */
	struct inode *vtable;	/* version table special file */
	struct inode *atable;	/* xattr atom special file */
	unsigned blocksize, blockbits, blockmask;
	block_t volblocks, freeblocks, nextalloc;
	unsigned entries_per_node; /* must be per-btree type, get rid of this */
	unsigned max_inodes_per_block; /* get rid of this and use entries per leaf */
	unsigned version;	/* Currently mounted volume version view */
	unsigned atomref_base, unatom_base; /* layout of atom table */
	unsigned freeatom;	/* Start of free atom list in atom table */
	unsigned atomgen;	/* Next atom number to allocate if no free atoms */
	loff_t dictsize;	/* Atom dictionary size */
	struct inode *logmap;	/* Prototype log block cache */
	unsigned lognext;	/* Index of next log block in log map */
	struct buffer_head *logbuf; /* Cached log block */
	unsigned char *logpos, *logtop; /* Where to emit next log entry */
	struct mutex loglock; /* serialize log entries (spinlock me) */
#ifdef __KERNEL__
	struct super_block *vfs_sb; /* Generic kernel superblock */
#else
	map_t *devmap; /* Userspace device block cache */
#endif
};

#ifdef __KERNEL__
/*
 * In kernel an inode has a generic part and a filesystem-specific part
 * with conversions between them, in order to support multiple different
 * kinds of filesystem.  In userspace there is only one kind of filesystem,
 * Tux3, so no need for two kinds of inodes, and a big pain to initialize
 * inodes for testing if there were.  We use a typedef here so that the
 * filesystem-specific type can be transparently aliased to the generic
 * inode type in userspace and be a separate type in kernel.
 */

typedef struct {
	struct btree btree;
	inum_t inum;		/* Inode number.  Fixme: also in generic inode */
	unsigned present;	/* Attributes decoded from or to be encoded to inode table */
	struct xcache *xcache;	/* Extended attribute cache */
	struct inode vfs_inode;	/* Generic kernel inode */
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
	loff_t i_size;
	unsigned i_version;
	struct timespec i_mtime, i_ctime, i_atime;
	unsigned i_mode, i_uid, i_gid, i_nlink;
	struct mutex i_mutex;
	dev_t i_rdev;
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

#define TUX_LINK_MAX 64		/* just for debug for now */

#define TUX_NAME_LEN 255

/* directory entry */
typedef struct {
	be_u64 inum;
	be_u16 rec_len;
	u8 name_len, type;
	char name[];
} tux_dirent;

/* version:10, count:6, block:48 */
struct diskextent { be_u64 block_count_version; };
#define MAX_GROUP_ENTRIES 255
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

static inline block_t extent_block(struct diskextent extent)
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

struct btree_ops {
	void (*btree_init)(struct btree *btree);
	int (*leaf_sniff)(struct btree *btree, vleaf *leaf);
	int (*leaf_init)(struct btree *btree, vleaf *leaf);
	tuxkey_t (*leaf_split)(struct btree *btree, tuxkey_t key, vleaf *from, vleaf *into);
	void *(*leaf_resize)(struct btree *btree, tuxkey_t key, vleaf *leaf, unsigned size);
	void (*leaf_dump)(struct btree *btree, vleaf *leaf);
	unsigned (*leaf_need)(struct btree *btree, vleaf *leaf);
	unsigned (*leaf_free)(struct btree *btree, vleaf *leaf);
	/* return value: 1 - modified, 0 - not modified, < 0 - error */
	int (*leaf_chop)(struct btree *btree, tuxkey_t key, vleaf *leaf);
	void (*leaf_merge)(struct btree *btree, vleaf *into, vleaf *from);
	block_t (*balloc)(struct sb *sb, unsigned blocks);
	void (*bfree)(struct sb *sb, block_t block, unsigned blocks);
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
	u64 mult = ((1ULL << 63) / 1000000000ULL);
	return ((u64)time.tv_sec << 32) + ((time.tv_nsec * mult + (3 << 29)) >> 31);
}

void hexdump(void *data, unsigned size);
block_t balloc(struct sb *sb, unsigned blocks);
void bfree(struct sb *sb, block_t start, unsigned blocks);
int update_bitmap(struct sb *sb, block_t start, unsigned count, int set);

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
static inline struct timespec gettime(void)
{
	return current_kernel_time();
}

struct tux_iattr {
	unsigned mode, uid, gid;
};

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

/* btree.c */
struct buffer_head *cursor_leafbuf(struct cursor *cursor);
void release_cursor(struct cursor *cursor);
struct cursor *alloc_cursor(struct btree *btree, int);
void free_cursor(struct cursor *cursor);
void level_pop_brelse_dirty(struct cursor *cursor);
void level_push(struct cursor *cursor, struct buffer_head *buffer, struct index_entry *next);

void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops);
int new_btree(struct btree *btree, struct sb *sb, struct btree_ops *ops);
struct buffer_head *new_leaf(struct btree *btree);
int probe(struct btree *btree, tuxkey_t key, struct cursor *cursor);
int advance(struct btree *btree, struct cursor *cursor);
tuxkey_t next_key(struct cursor *cursor, int depth);
int tree_chop(struct btree *btree, struct delete_info *info, millisecond_t deadline);
int btree_insert_leaf(struct cursor *cursor, tuxkey_t key, struct buffer_head *leafbuf);
int btree_leaf_split(struct btree *btree, struct cursor *cursor, tuxkey_t key);
void *tree_expand(struct btree *btree, tuxkey_t key, unsigned newsize, struct cursor *cursor);
void show_tree_range(struct btree *btree, tuxkey_t start, unsigned count);
void show_tree(struct btree *btree);

/* dir.c */
int tux_update_entry(struct buffer_head *buffer, tux_dirent *entry, inum_t inum, unsigned mode);
loff_t tux_create_entry(struct inode *dir, const char *name, int len, inum_t inum, unsigned mode);
tux_dirent *tux_find_entry(struct inode *dir, const char *name, int len, struct buffer_head **result);
int tux_delete_entry(struct buffer_head *buffer, tux_dirent *entry);
int tux_readdir(struct file *file, void *state, filldir_t filldir);
int tux_dir_is_empty(struct inode *dir);
extern const struct file_operations tux_dir_fops;
extern const struct inode_operations tux_dir_iops;

/* dtree.c */
int dleaf_init(struct btree *btree, vleaf *leaf);
unsigned dleaf_free(struct btree *btree, vleaf *leaf);
void dleaf_dump(struct btree *btree, vleaf *vleaf);
int dleaf_split_at(vleaf *from, vleaf *into, struct entry *entry, unsigned blocksize);
void dleaf_merge(struct btree *btree, vleaf *vinto, vleaf *vfrom);
unsigned dleaf_need(struct btree *btree, vleaf *vleaf);
extern struct btree_ops dtree_ops;

int dwalk_end(struct dwalk *walk);
block_t dwalk_block(struct dwalk *walk);
unsigned dwalk_count(struct dwalk *walk);
tuxkey_t dwalk_index(struct dwalk *walk);
int dwalk_next(struct dwalk *walk);
int dwalk_back(struct dwalk *walk);
int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key);
int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct diskextent extent);
void dwalk_copy(struct dwalk *walk, struct dleaf *dest);
void dwalk_chop(struct dwalk *walk);
int dwalk_add(struct dwalk *walk, tuxkey_t index, struct diskextent extent);

/* filemap.c */
int tux3_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create);
extern const struct address_space_operations tux_aops;
extern const struct address_space_operations tux_blk_aops;

/* iattr.c */
unsigned encode_asize(unsigned bits);
void dump_attrs(struct inode *inode);
void *encode_attrs(struct inode *inode, void *attrs, unsigned size);
void *decode_attrs(struct inode *inode, void *attrs, unsigned size);

/* ileaf.c */
void *ileaf_lookup(struct btree *btree, inum_t inum, struct ileaf *leaf, unsigned *result);
inum_t find_empty_inode(struct btree *btree, struct ileaf *leaf, inum_t goal);
int ileaf_purge(struct btree *btree, inum_t inum, struct ileaf *leaf);
extern struct btree_ops itable_ops;

/* inode.c */
void tux3_delete_inode(struct inode *inode);
void tux3_clear_inode(struct inode *inode);
int tux3_write_inode(struct inode *inode, int do_sync);
int tux3_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
struct inode *tux_create_inode(struct inode *dir, int mode, dev_t rdev);
struct inode *tux3_iget(struct super_block *sb, inum_t inum);
int tux3_setattr(struct dentry *dentry, struct iattr *iattr);

/* symlink.c */
extern const struct inode_operations tux_symlink_iops;

/* xattr.c */
int xcache_dump(struct inode *inode);
struct xcache *new_xcache(unsigned maxsize);
int get_xattr(struct inode *inode, const char *name, unsigned len, void *data, unsigned size);
int set_xattr(struct inode *inode, const char *name, unsigned len, const void *data, unsigned size, unsigned flags);
void *encode_xattrs(struct inode *inode, void *attrs, unsigned size);
unsigned decode_xsize(struct inode *inode, void *attrs, unsigned size);
unsigned encode_xsize(struct inode *inode);

/* commit.c */
int unpack_sb(struct sb *sb, struct disksuper *super, int silent);
void pack_sb(struct sb *sb, struct disksuper *super);

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

static inline void begin_change(struct sb *sb) { };
static inline void end_change(struct sb *sb) { };
#endif
