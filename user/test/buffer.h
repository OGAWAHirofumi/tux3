#ifndef BUFFER_H
#define BUFFER_H

#define BUFFER_STATE_EMPTY 1
#define BUFFER_STATE_CLEAN 2
#define BUFFER_STATE_DIRTY 3
#define BUFFER_STATE_JOURNALED 4
#define BUFFER_BUCKETS 9999

#include "list.h"

typedef unsigned long long sector_t;
typedef unsigned long long offset_t;

struct dev { unsigned fd, blockbits; };

struct buffer
{
	struct buffer *hashlist;
	struct list_head dirty_list;
	struct list_head list; /* used for LRU list and the free list */
	unsigned count; // should be atomic_t
	unsigned state;
	unsigned size;
	sector_t block;
	unsigned char *data;
	struct dev *dev;
};

struct list_head dirty_buffers;
extern unsigned dirty_buffer_count;
struct list_head journaled_buffers;
extern unsigned journaled_count;

void show_dirty_buffers(void);
void set_buffer_dirty(struct buffer *buffer);
void set_buffer_uptodate(struct buffer *buffer);
void set_buffer_empty(struct buffer *buffer);
void brelse(struct buffer *buffer);
void brelse_dirty(struct buffer *buffer);
int write_buffer_to(struct buffer *buffer, offset_t pos);
int write_buffer(struct buffer *buffer);
int read_buffer(struct buffer *buffer);
unsigned buffer_hash(sector_t block);
struct buffer *new_buffer(struct dev *dev, sector_t block);
struct buffer *getblk(struct dev *dev, sector_t block);
struct buffer *bread(struct dev *dev, sector_t block);
void evict_buffer(struct buffer *buffer);
void evict_buffers(void);
int flush_buffers(void);
void show_buffer(struct buffer *buffer);
void show_active_buffers(void);
void show_buffers(void);
void init_buffers(unsigned bufsize, unsigned mem_pool_size);
void add_buffer_journaled(struct buffer *buffer);

static inline unsigned buffer_size(struct buffer *buffer)
{
	return 1 << buffer->dev->blockbits;
}

static inline int buffer_dirty(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_DIRTY;
}

static inline int buffer_uptodate(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_CLEAN;
}

static inline int buffer_journaled(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_JOURNALED;
}

static inline void *malloc_aligned(size_t size, unsigned binalign)
{
	unsigned long p = (unsigned long)malloc(size + binalign - 1);
	return (void *)(p + (-p & (binalign - 1)));
}

int count_buffer(void);
#endif
