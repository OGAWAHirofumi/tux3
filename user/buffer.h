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

typedef int (blockio_t)(int rw, struct bufvec *bufvec);

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
static inline unsigned tux3_bufdelta(struct buffer_head *buffer)
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
	if (tux3_bufdelta(buffer) == delta_when(delta))
		return 1;
	/* The buffer may already be in stabilized stage for backend. */
	return 0;
}

struct buffer_head *new_buffer(map_t *map);
void show_buffer(struct buffer_head *buffer);
void show_buffers(map_t *map);
void show_active_buffers(map_t *map);
void show_dirty_buffers(map_t *map);
void show_buffers_state(unsigned state);
void set_buffer_state_list(struct buffer_head *buffer, unsigned state, struct list_head *list);
void tux3_set_buffer_dirty_list(struct buffer_head *buffer, int delta,
				struct list_head *head);
void tux3_set_buffer_dirty(struct buffer_head *buffer, int delta);
struct buffer_head *set_buffer_dirty(struct buffer_head *buffer);
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
void truncate_buffers_range(map_t *map, loff_t lstart, loff_t lend);
void invalidate_buffers(map_t *map);
void init_buffers(struct dev *dev, unsigned poolsize, int debug);
int dev_errio(int rw, struct bufvec *bufvec);
void init_dirty_buffers(struct dirty_buffers *dirty);
map_t *new_map(struct dev *dev, blockio_t *io);
void free_map(map_t *map);

/* buffer_writeback.c */
/* Helper for waiting I/O (stub) */
struct iowait {
};

/* I/O completion callback */
typedef void (*bufvec_end_io_t)(struct buffer_head *buffer, int err);

/* Helper for buffer vector I/O */
struct bufvec {
	struct list_head *buffers;	/* The dirty buffers for this delta */
	struct list_head contig;	/* One logical contiguous range */
	unsigned contig_count;		/* Count of contiguous buffers */

	struct list_head for_io;	/* The buffers in iovec */

	bufvec_end_io_t end_io;
};

static inline unsigned bufvec_contig_count(struct bufvec *bufvec)
{
	return bufvec->contig_count;
}

static inline struct buffer_head *bufvec_contig_buf(struct bufvec *bufvec)
{
	struct list_head *first = bufvec->contig.next;
	assert(!list_empty(&bufvec->contig));
	return list_entry(first, struct buffer_head, link);
}

static inline block_t bufvec_contig_index(struct bufvec *bufvec)
{
	return bufindex(bufvec_contig_buf(bufvec));
}

static inline block_t bufvec_contig_last_index(struct bufvec *bufvec)
{
	return bufvec_contig_index(bufvec) + bufvec_contig_count(bufvec) - 1;
}

void tux3_iowait_init(struct iowait *iowait);
void tux3_iowait_wait(struct iowait *iowait);
void bufvec_init(struct bufvec *bufvec, struct list_head *head);
void bufvec_free(struct bufvec *bufvec);
int bufvec_contig_add(struct bufvec *bufvec, struct buffer_head *buffer);
int bufvec_io(int rw, struct bufvec *bufvec, block_t physical, unsigned count);
void bufvec_complete_without_io(struct bufvec *bufvec, unsigned count);
int flush_list(struct list_head *head);
int flush_buffers(map_t *map);
int flush_state(unsigned state);
#endif
