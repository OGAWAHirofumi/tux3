#ifndef TUX3_USER_H
#define TUX3_USER_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "buffer.h"
#include "trace.h"

#include "libklib/libklib.h"
#include "libklib/lockdebug.h"
#include "libklib/mm.h"
#include "libklib/fs.h"
#include "writeback.h"

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

#include "kernel/tux3.h"

#ifdef ATOMIC
#define INIT_DISKSB_FREEBLOCKS(_blocks)
#else
#define INIT_DISKSB_FREEBLOCKS(_blocks)	.freeblocks = cpu_to_be64(_blocks)
#endif
#define INIT_DISKSB(_bits, _blocks) {				\
	.magic		= TUX3_MAGIC,				\
	.birthdate	= 0,					\
	.flags		= 0,					\
	.iroot		= cpu_to_be64(pack_root(&no_root)),	\
	.oroot		= cpu_to_be64(pack_root(&no_root)),	\
	.blockbits	= cpu_to_be16(_bits),			\
	.volblocks	= cpu_to_be64(_blocks),			\
	.atomdictsize	= 0,					\
	.freeatom	= 0,					\
	.atomgen	= cpu_to_be32(1),			\
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
	.dirty_list = LIST_HEAD_INIT((inode).dirty_list),	\
	.alloc_list = LIST_HEAD_INIT((inode).alloc_list),	\
	.orphan_list = LIST_HEAD_INIT((inode).orphan_list)

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
int make_tux3(struct sb *sb);

/* utility.c */
void stacktrace(void);
int devio(int rw, struct dev *dev, loff_t offset, void *data, unsigned len);
int devio_vec(int rw, struct dev *dev, loff_t offset, struct iovec *iov,
	      unsigned iovcnt);
int blockio(int rw, struct buffer_head *buffer, block_t block);
int blockio_vec(int rw, struct bufvec *bufvec, unsigned count, block_t block);

#endif /* !TUX3_USER_H */
