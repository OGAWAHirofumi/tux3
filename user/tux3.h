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

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int fd_t;

struct rw_semaphore { };

static inline void down_read_nested(struct rw_semaphore *sem, int sub) { };
static inline void down_read(struct rw_semaphore *sem) { };
static inline void down_write_nested(struct rw_semaphore *sem, int sub) { };
static inline void down_write(struct rw_semaphore *sem) { };
static inline void up_read(struct rw_semaphore *sem) { };
static inline void up_write(struct rw_semaphore *sem) { };
static inline void init_rwsem(struct rw_semaphore *sem) { };

struct mutex { };

static inline void mutex_lock_nested(struct mutex *mutex, unsigned int sub) { };
static inline void mutex_lock(struct mutex *mutex) { };
static inline void mutex_unlock(struct mutex *mutex) { };

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

static inline struct buffer_head *sb_getblk(struct sb *sb, block_t block)
{
	return blockget(sb->volmap->map, block);
}

static inline struct buffer_head *sb_bread(struct sb *sb, block_t block)
{
	return blockread(sb->volmap->map, block);
}

#define rapid_new_inode(sb, ops, mode)	({			\
	struct inode *__inode = &(struct inode){		\
		.i_sb = sb,					\
		.i_mode = mode,					\
	};							\
	__inode->map = new_map((sb)->dev, ops);			\
	assert(__inode->map);					\
	__inode->map->inode = __inode;				\
	__inode;						\
})

#define RAPID_INIT_SB(dev)			\
	.dev = dev,				\
	.blockbits = (dev)->bits,		\
	.blocksize = 1 << (dev)->bits,		\
	.blockmask = ((1 << (dev)->bits) - 1)

enum { DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK };
typedef int (filldir_t)(void *dirent, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type);

#endif
