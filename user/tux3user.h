#ifndef TUX3_USER_H
#define TUX3_USER_H

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
#include "buffer.h"
#include "trace.h"

#include "libklib/libklib.h"
#include "libklib/mm.h"
#include "writeback.h"

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

static inline be_u16 __to_be_u16(u16 val)
{
	return (__force be_u16)bswap_16(val);
}
#define to_be_u16(__x)						\
	(__builtin_constant_p((u16)(__x)) ?			\
	 (__force be_u16)__bswap_constant_16((u16)(__x)) :	\
	 __to_be_u16(__x))

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

#include "kernel/dirty-buffer.h"	/* remove this after atomic commit */

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

#ifdef ATOMIC
#define INIT_DISKSB_FREEBLOCKS(_blocks)
#else
#define INIT_DISKSB_FREEBLOCKS(_blocks)	.freeblocks = to_be_u64(_blocks)
#endif
#define INIT_DISKSB(_bits, _blocks) {				\
	.magic		= TUX3_MAGIC,				\
	.birthdate	= 0,					\
	.flags		= 0,					\
	.iroot		= to_be_u64(pack_root(&no_root)),	\
	.oroot		= to_be_u64(pack_root(&no_root)),	\
	.blockbits	= to_be_u16(_bits),			\
	.volblocks	= to_be_u64(_blocks),			\
	.atomdictsize	= 0,					\
	.freeatom	= 0,					\
	.atomgen	= to_be_u32(1),				\
	.logchain	= 0,					\
	.logcount	= 0,					\
	INIT_DISKSB_FREEBLOCKS(_blocks)				\
}

#define INIT_INODE(inode, sb, mode)				\
	.i_sb = sb,						\
	.i_mode = mode,						\
	.i_mutex = __MUTEX_INITIALIZER,				\
	.i_version = 1,						\
	.i_nlink = 1,						\
	.i_count = ATOMIC_INIT(1),				\
	.alloc_list = LIST_HEAD_INIT((inode).alloc_list),	\
	.orphan_list = LIST_HEAD_INIT((inode).orphan_list),	\
	.list = LIST_HEAD_INIT((inode).list)

#define rapid_open_inode(sb, io, mode, init_defs...) ({		\
	struct inode *__inode = &(struct inode){};		\
	*__inode = (struct inode){				\
		INIT_INODE(*__inode, sb, mode),			\
		.btree = {					\
			.lock = __RWSEM_INITIALIZER,		\
		},						\
		init_defs					\
	};							\
	INIT_HLIST_NODE(&__inode->i_hash);			\
	__inode->map = new_map((sb)->dev, io);			\
	assert(__inode->map);					\
	__inode->map->inode = __inode;				\
	__inode;						\
	})

#define rapid_sb(x)	(&(struct sb){ .dev = x })

/* dir.c */
void tux_dump_entries(struct buffer_head *buffer);

/* filemap.c */
int filemap_overwrite_io(struct buffer_head *buffer, int write);
int filemap_redirect_io(struct buffer_head *buffer, int write);
int write_bitmap(struct buffer_head *buffer);
int tuxread(struct file *file, void *data, unsigned len);
int tuxwrite(struct file *file, const void *data, unsigned len);
void tuxseek(struct file *file, loff_t pos);
int page_symlink(struct inode *inode, const char *symname, int len);
int page_readlink(struct inode *inode, void *buf, unsigned size);

/* inode.c */
void inode_leak_check(void);
void __iget(struct inode *inode);
void ihold(struct inode *inode);
struct inode *tux3_ilookup(struct sb *sb, inum_t inum);
void iput(struct inode *inode);
int tuxtruncate(struct inode *inode, loff_t size);
int write_inode(struct inode *inode);

/* namei.c */
struct inode *tuxopen(struct inode *dir, const char *name, unsigned len);
struct inode *__tuxmknod(struct inode *dir, const char *name, unsigned len,
			 struct tux_iattr *iattr, dev_t rdev);
struct inode *tuxcreate(struct inode *dir, const char *name, unsigned len,
			struct tux_iattr *iattr);
struct inode *__tuxlink(struct inode *src_inode, struct inode *dir,
			const char *dstname, unsigned dstlen);
int tuxlink(struct inode *dir, const char *srcname, unsigned srclen,
	    const char *dstname, unsigned dstlen);
struct inode *__tuxsymlink(struct inode *dir, const char *name, unsigned len,
			   struct tux_iattr *iattr, const char *symname);
int tuxsymlink(struct inode *dir, const char *name, unsigned len,
	       struct tux_iattr *iattr, const char *symname);
int tuxunlink(struct inode *dir, const char *name, unsigned len);
int tuxrmdir(struct inode *dir, const char *name, unsigned len);
int tuxrename(struct inode *old_dir, const char *old_name, unsigned old_len,
	      struct inode *new_dir, const char *new_name, unsigned new_len);

/* super.c */
int put_super(struct sb *sb);
struct inode *iget_or_create_inode(struct sb *sb, inum_t inum);
int make_tux3(struct sb *sb);

/* utility.c */
void stacktrace(void);
int devio(int rw, struct dev *dev, loff_t offset, void *data, unsigned len);
int blockio(int rw, struct buffer_head *buffer, block_t block);

#endif /* !TUX3_USER_H */
