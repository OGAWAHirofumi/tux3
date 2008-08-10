#ifndef BUFFER_H
#define BUFFER_H

#define BUFFER_STATE_EMPTY 1
#define BUFFER_STATE_CLEAN 2
#define BUFFER_STATE_DIRTY 3
#define BUFFER_STATE_JOURNALED 4
#define BUFFER_BUCKETS 999

#include "list.h"

typedef unsigned long long sector_t;
typedef unsigned long long offset_t;

struct dev { unsigned fd, bits; };

struct buffer;

struct map_ops
{
	int (*readbuf)(struct buffer *buffer);
	int (*writebuf)(struct buffer *buffer);
};

struct map {
	struct sb *sb;
	struct dev *dev;
	struct map_ops ops;
	struct buffer *hash[BUFFER_BUCKETS];
	struct list_head dirty;
	unsigned dirty_count;
};

struct buffer
{
	struct map *map;
	struct buffer *hashlink;
	struct list_head dirtylink;
	struct list_head lrulink; /* used for LRU list and the free list */
	unsigned count; // should be atomic_t
	unsigned state;
	unsigned size;
	sector_t block;
	void *data;
};

struct list_head dirty_buffers;
extern unsigned dirty_buffer_count;
struct list_head journaled_buffers;
extern unsigned journaled_count;

void set_buffer_dirty(struct buffer *buffer);
void set_buffer_uptodate(struct buffer *buffer);
void set_buffer_empty(struct buffer *buffer);
void brelse(struct buffer *buffer);
void brelse_dirty(struct buffer *buffer);
int write_buffer_to(struct buffer *buffer, offset_t pos);
int write_buffer(struct buffer *buffer);
int read_buffer(struct buffer *buffer);
unsigned buffer_hash(sector_t block);
struct buffer *getblk(struct map *map, sector_t block);
struct buffer *bread(struct map *map, sector_t block);
void add_buffer_journaled(struct buffer *buffer);
void init_buffers(struct map *map, unsigned poolsize);
int flush_buffers(struct map *map);

static inline unsigned bufsize(struct buffer *buffer)
{
	return 1 << buffer->map->dev->bits;
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
