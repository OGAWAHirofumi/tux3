#ifndef USER_TUX3_H
#define USER_TUX3_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <byteswap.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "err.h"
#include "buffer.h"
#include "trace.h"
#include "lockdebug.h"
#include "utility.h"
#include "kernel/link.h"

void stacktrace(void);
void hexdump(void *data, unsigned size);

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

#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))

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

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

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

#include "writeback.h"
#include "kernel/tux3.h"

static inline struct inode *buffer_inode(struct buffer_head *buffer)
{
	return buffer->map->inode;
}

static inline struct timespec gettime(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return (struct timespec){ .tv_sec = now.tv_sec, .tv_nsec = now.tv_usec * 1000 };
}

struct tux_iattr {
	unsigned mode, uid, gid;
};

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

#define INIT_INODE(inode, sb, mode)				\
	.i_sb = sb,						\
	.i_mode = mode,						\
	.i_mutex = __MUTEX_INITIALIZER,				\
	.i_version = 1,						\
	.i_nlink = 1,						\
	.i_count = ATOMIC_INIT(1),				\
	.alloc_list = LIST_HEAD_INIT((inode).alloc_list),	\
	.list = LIST_HEAD_INIT((inode).list)

#define INIT_SB(sb, dev)					\
	.dev = dev,						\
	.blockbits = (dev)->bits,				\
	.blocksize = 1 << (dev)->bits,				\
	.blockmask = ((1 << (dev)->bits) - 1),			\
	.delta_lock = __RWSEM_INITIALIZER,			\
	.loglock = __MUTEX_INITIALIZER,				\
	.alloc_inodes = LIST_HEAD_INIT((sb).alloc_inodes),	\
	.dirty_inodes = LIST_HEAD_INIT((sb).dirty_inodes),	\
	.commit = LIST_HEAD_INIT((sb).commit),			\
	.pinned = LIST_HEAD_INIT((sb).pinned)

#define rapid_open_inode(sb, io, mode, init_defs...) ({		\
	struct inode *__inode = &(struct inode){};		\
	*__inode = (struct inode){				\
		INIT_INODE(*__inode, sb, mode),			\
		.btree = {					\
			.lock = __RWSEM_INITIALIZER,		\
		},						\
		init_defs					\
	};							\
	__inode->map = new_map((sb)->dev, io);			\
	assert(__inode->map);					\
	__inode->map->inode = __inode;				\
	__inode;						\
	})

#define rapid_sb(dev, init_defs...) ({				\
	struct sb *__sb = &(struct sb){};			\
	*__sb = (struct sb){					\
		INIT_SB(*__sb, dev),				\
		init_defs					\
	};							\
	__sb;							\
	});

enum { DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK };
typedef int (filldir_t)(void *dirent, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type);

enum rw { READ, WRITE };

int change_begin(struct sb *sb);
int change_end(struct sb *sb);
int write_bitmap(struct buffer_head *buffer);

#endif
