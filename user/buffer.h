#ifndef BUFFER_H
#define BUFFER_H

#define BUFFER_STATE_EMPTY 1
#define BUFFER_STATE_CLEAN 2
#define BUFFER_STATE_DIRTY 3
#define BUFFER_STATE_JOURNALED 4
#define BUFFER_BUCKETS 999

#include "list.h"

typedef loff_t block_t; // disk io address range
typedef block_t index_t; // block cache address range

struct dev { unsigned fd, bits; };

struct buffer;

struct map_ops
{
	int (*blockio)(struct buffer *buffer, int write);
	int (*blockwrite)(struct buffer *buffer);
	int (*blockread)(struct buffer *buffer);
};

struct map {
	struct list_head dirty;
	struct inode *inode;
	struct dev *dev;
	struct map_ops *ops;
	struct buffer *hash[BUFFER_BUCKETS];
	unsigned dirty_count;
};

typedef struct map map_t;

struct buffer
{
	map_t *map;
	struct buffer *hashlink;
	struct list_head dirtylink;
	struct list_head lrulink; /* used for LRU list and the free list */
	unsigned count, state; // should be atomic_t
	index_t index;
	void *data;
};

struct list_head dirty_buffers;
extern unsigned dirty_buffer_count;
struct list_head journaled_buffers;
extern unsigned journaled_count;

void show_buffer(struct buffer *buffer);
void show_buffers(map_t *map);
struct buffer *set_buffer_dirty(struct buffer *buffer);
struct buffer *set_buffer_uptodate(struct buffer *buffer);
struct buffer *set_buffer_empty(struct buffer *buffer);
void brelse(struct buffer *buffer);
void brelse_dirty(struct buffer *buffer);
int write_buffer_to(struct buffer *buffer, block_t pos);
int write_buffer(struct buffer *buffer);
int read_buffer(struct buffer *buffer);
unsigned buffer_hash(block_t block);
struct buffer *peekblk(map_t *map, block_t block);
struct buffer *blockget(map_t *map, block_t block);
struct buffer *blockread(map_t *map, block_t block);
void add_buffer_journaled(struct buffer *buffer);
int flush_buffers(map_t *map);
void evict_buffers(map_t *map);
void init_buffers(struct dev *dev, unsigned poolsize);

static inline unsigned bufsize(struct buffer *buffer)
{
	return 1 << buffer->map->dev->bits;
}

static inline int buffer_empty(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_EMPTY;
}

static inline int buffer_uptodate(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_CLEAN;
}

static inline int buffer_dirty(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_DIRTY;
}

static inline int buffer_journaled(struct buffer *buffer)
{
	return buffer->state == BUFFER_STATE_JOURNALED;
}

map_t *new_map(struct dev *dev, struct map_ops *ops); // new_map should take inode *??? does it belong here???
void free_map(map_t *map);
#endif
