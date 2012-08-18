#ifndef BUFFER_H
#define BUFFER_H

#define BUFFER_FOR_TUX3

#ifdef BUFFER_FOR_TUX3
#include "trace.h"
#endif
#include "libklib/list.h"
#include <sys/uio.h>

#define BUFFER_DIRTY_STATES	4
#define DEFAULT_DIRTY_WHEN	0

enum {
	BUFFER_FREED, BUFFER_EMPTY, BUFFER_CLEAN, BUFFER_DIRTY,
	BUFFER_STATES = BUFFER_DIRTY + BUFFER_DIRTY_STATES
};

#define BUFFER_BUCKETS 999

// disk io address range
#ifdef BUFFER_FOR_TUX3
/*
 * Choose carefully:
 * loff_t can be "long" or "long long" in userland. (not printf friendly)
 * sector_t can be "unsigned long" or "u64". (32bits arch 32bits is too small)
 *
 * we want 48bits for tux3, and error friendly. (FIXME: u64 is better?)
 */
typedef signed long long	block_t;
#else
typedef loff_t			block_t;
#endif

struct dev { unsigned fd, bits; };

struct buffer_head;
struct bufvec;

typedef int (blockio_t)(struct bufvec *bufvec, int rw);

struct dirty_buffers {
	struct list_head heads[BUFFER_DIRTY_STATES];
};

struct map {
#ifdef BUFFER_FOR_TUX3
	struct inode *inode;
#endif
	struct dirty_buffers dirty;
	struct dev *dev;
	blockio_t *io;
	struct hlist_head hash[BUFFER_BUCKETS];
};

typedef struct map map_t;

struct buffer_head {
	map_t *map;
	struct hlist_node hashlink;
	struct list_head link;
	struct list_head lru; /* used for LRU list and the free list */
	unsigned count, state;
	block_t index;
	void *data;
};

static inline void *bufdata(struct buffer_head *buffer)
{
	return buffer->data;
}

static inline unsigned bufsize(struct buffer_head *buffer)
{
	return 1 << buffer->map->dev->bits;
}

static inline block_t bufindex(struct buffer_head *buffer)
{
	return buffer->index;
}

static inline int bufcount(struct buffer_head *buffer)
{
	return buffer->count;
}

static inline int buffer_empty(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_EMPTY;
}

static inline int buffer_clean(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_CLEAN;
}

static inline int buffer_dirty(struct buffer_head *buffer)
{
	return buffer->state >= BUFFER_DIRTY;
}

/* When buffer was dirtied */
static inline unsigned buffer_dirty_when(struct buffer_head *buffer)
{
#ifdef assert
	assert(buffer_dirty(buffer));
#endif
	return buffer->state - BUFFER_DIRTY;
}

/* Get offset of delta */
static inline unsigned delta_when(unsigned delta)
{
	return delta & (BUFFER_DIRTY_STATES - 1);
}

/* Get list of buffers when dirtied at delta */
static inline struct list_head *
dirty_head_when(struct dirty_buffers *dirty, unsigned delta)
{
	return &dirty->heads[delta_when(delta)];
}

static inline struct list_head *dirty_head(struct dirty_buffers *dirty)
{
	return dirty_head_when(dirty, DEFAULT_DIRTY_WHEN);
}

/* Can we modify buffer from delta */
static inline int buffer_can_modify(struct buffer_head *buffer, unsigned delta)
{
	/* If true, buffer is still not stabilized. We can modify. */
	if (buffer_dirty_when(buffer) == delta_when(delta))
		return 1;
	/* The buffer may already be in stabilized stage for backend. */
	return 0;
}

/* Vector for I/O */
struct bufvec {
	struct buffer_head **bufv;
	struct iovec *iov;
	unsigned pos;			/* next position for I/O */
	unsigned count;			/* in-use count of array */
	unsigned max_count;		/* maximum count of array */
};

static inline unsigned bufvec_inuse(struct bufvec *bufvec)
{
	return bufvec->count - bufvec->pos;
}

static inline unsigned bufvec_space(struct bufvec *bufvec)
{
	return bufvec->max_count - bufvec_inuse(bufvec);
}

static inline struct buffer_head **bufvec_bufv(struct bufvec *bufvec)
{
	return &bufvec->bufv[bufvec->pos];
}

static inline struct buffer_head *bufvec_first_buf(struct bufvec *bufvec)
{
	return bufvec->bufv[bufvec->pos];
}

static inline struct buffer_head *bufvec_last_buf(struct bufvec *bufvec)
{
	return bufvec->bufv[bufvec->count - 1];
}

static inline struct iovec *bufvec_iov(struct bufvec *bufvec)
{
	return &bufvec->iov[bufvec->pos];
}

static inline block_t bufvec_first_index(struct bufvec *bufvec)
{
	return bufindex(bufvec_first_buf(bufvec));
}

static inline block_t bufvec_last_index(struct bufvec *bufvec)
{
	return bufindex(bufvec_last_buf(bufvec));
}

struct buffer_head *new_buffer(map_t *map);
void show_buffer(struct buffer_head *buffer);
void show_buffers(map_t *map);
void show_active_buffers(map_t *map);
void show_dirty_buffers(map_t *map);
void set_buffer_state_list(struct buffer_head *buffer, unsigned state, struct list_head *list);
void show_buffers_state(unsigned state);
struct buffer_head *set_buffer_dirty(struct buffer_head *buffer);
struct buffer_head *set_buffer_dirty_when(struct buffer_head *buffer, int delta);
struct buffer_head *set_buffer_clean(struct buffer_head *buffer);
struct buffer_head *set_buffer_empty(struct buffer_head *buffer);
void get_bh(struct buffer_head *buffer);
void blockput_free(struct buffer_head *buffer);
void blockput(struct buffer_head *buffer);
unsigned buffer_hash(block_t block);
struct buffer_head *peekblk(map_t *map, block_t block);
struct buffer_head *blockget(map_t *map, block_t block);
struct buffer_head *blockread(map_t *map, block_t block);
void insert_buffer_hash(struct buffer_head *buffer);
void remove_buffer_hash(struct buffer_head *buffer);
int flush_list(struct list_head *list);
int flush_buffers_when(map_t *map, unsigned delta);
int flush_buffers(map_t *map);
int flush_state(unsigned state);
void truncate_buffers_range(map_t *map, loff_t lstart, loff_t lend);
void invalidate_buffers(map_t *map);
void init_buffers(struct dev *dev, unsigned poolsize, int debug);
int dev_errio(struct bufvec *bufvec, int rw);
void init_dirty_buffers(struct dirty_buffers *dirty);
map_t *new_map(struct dev *dev, blockio_t *io);
void free_map(map_t *map);

void bufvec_free(struct bufvec *bufvec);
struct bufvec *bufvec_alloc(unsigned max_count);
int bufvec_add(struct bufvec *bufvec, struct buffer_head *buffer);
void bufvec_io_done(struct bufvec *bufvec, unsigned done_count);
#endif
