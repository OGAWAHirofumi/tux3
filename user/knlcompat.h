#ifndef TUX3_KERNEL_COMPAT_H
#define TUX3_KERNEL_COMPAT_H

#include <stdint.h>
#include <limits.h>
#include <endian.h>
#include "list.h"
#include "err.h"
#include "lockdebug.h"

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

#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))

#ifdef __GNUC__
/*
 * A trick to suppress uninitialized variable warning without generating any
 * code
 */
#define uninitialized_var(x) x = x
#else
#define uninitialized_var(x) x
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef unsigned short umode_t;

#define BITS_PER_LONG		LONG_BIT	/* SuS define this */
#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}
#define ffz(x)			__ffs(~(x))

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset);
#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)
unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset);
#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BITOP_LE_SWIZZLE	0
static inline unsigned long find_next_zero_bit_le(const void *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_zero_bit(addr, size, offset);
}

static inline unsigned long find_next_bit_le(const void *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_bit(addr, size, offset);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BITOP_LE_SWIZZLE	((BITS_PER_LONG-1) & ~0x7)
extern unsigned long find_next_zero_bit_le(const void *addr,
		unsigned long size, unsigned long offset);
extern unsigned long find_next_bit_le(const void *addr,
		unsigned long size, unsigned long offset);
#endif /* !__BIG_ENDIAN */

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

typedef unsigned __bitwise__ gfp_t;

#define GFP_KERNEL	(__force gfp_t)0x10u
#define GFP_NOFS	(__force gfp_t)0x20u

struct page { void *address; unsigned long private; };

#define PAGE_SIZE (1 << 6)

static inline void *page_address(struct page *page)
{
	return page->address;
}

static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned order)
{
	struct page *page = malloc(sizeof(*page));
	void *data = malloc(PAGE_SIZE);
	if (!page || !data)
		goto error;
	*page = (struct page){ .address = data };
	return page;

error:
	if (page)
		free(page);
	if (data)
		free(data);
	return NULL;
}
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

static inline void __free_pages(struct page *page, unsigned order)
{
	free(page_address(page));
	free(page);
}
#define __free_page(page) __free_pages((page), 0)

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

static inline void truncate_inode_pages_range(map_t *map, loff_t lstart, loff_t lend)
{
	truncate_buffers_range(map, lstart, lend);
}

static inline void truncate_inode_pages(map_t *map, loff_t lstart)
{
	truncate_buffers_range(map, lstart, LLONG_MAX);
}

#endif /* !TUX3_KERNEL_COMPAT_H */
