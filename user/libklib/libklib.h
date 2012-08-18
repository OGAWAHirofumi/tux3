#ifndef LIBKLIB_H
#define LIBKLIB_H

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <endian.h>
#include <sys/types.h>

#include <libklib/list.h>
#include <libklib/err.h>
#include <libklib/compiler.h>
#include <libklib/types.h>
#include <libklib/bitops.h>

#ifdef __CHECKER__
#define BUILD_BUG_ON(condition)
#else /* __CHECKER__ */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)					\
	do {							\
		((void)sizeof(char[1 - 2*!!(condition)]));	\
		if (condition) __build_bug_on_failed = 1;	\
	} while(0)
#endif
#endif /* __CHECKER__ */

#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

/*
 * min()/max()/clamp() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max/clamp at all, of course.
 */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if BITS_PER_LONG == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif BITS_PER_LONG == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

/* Kernel page emulation for deferred free support */

struct nameidata {
};

struct qstr {
	/* unsigned int hash; */
	unsigned int len;
	const unsigned char *name;
};

struct dentry {
	struct qstr d_name;
	struct inode *d_inode;
};

void d_instantiate(struct dentry *dentry, struct inode *inode);
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry);

void inc_nlink(struct inode *inode);
void drop_nlink(struct inode *inode);
void clear_nlink(struct inode *inode);
void set_nlink(struct inode *inode, unsigned int nlink);

void mark_inode_dirty(struct inode *inode);
static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

/*
 * File types
 *
 * NOTE! These match bits 12..15 of stat.st_mode
 * (ie "(i_mode >> 12) & 15").
 */
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

typedef int (*filldir_t)(void *, const char *, int, loff_t, u64, unsigned);

enum rw { READ, WRITE };

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline dev_t new_decode_dev(u32 dev)
{
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return MKDEV(major, minor);
}

static inline int huge_valid_dev(dev_t dev)
{
	return 1;
}

static inline u64 huge_encode_dev(dev_t dev)
{
	return new_encode_dev(dev);
}

static inline dev_t huge_decode_dev(u64 dev)
{
	return new_decode_dev(dev);
}
#endif /* !LIBKLIB_H */
