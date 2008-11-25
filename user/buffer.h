#ifndef BUFFER_H
#define BUFFER_H

#define BUFFER_STATE_EMPTY 1
#define BUFFER_STATE_CLEAN 2
#define BUFFER_STATE_DIRTY 3
#define BUFFER_STATE_JOURNALED 4
#define BUFFER_BUCKETS 999

#include "list.h"

typedef loff_t block_t; // disk io address range

struct dev { unsigned fd, bits; };

struct buffer_head;

struct map_ops
{
	int (*blockio)(struct buffer_head *buffer, int write);
	int (*blockwrite)(struct buffer_head *buffer);
	int (*blockread)(struct buffer_head *buffer);
};

struct map {
	struct list_head dirty;
	struct inode *inode;
	struct dev *dev;
	struct map_ops *ops;
	struct buffer_head *hash[BUFFER_BUCKETS];
	unsigned dirty_count;
};

typedef struct map map_t;

struct buffer_head
{
	map_t *map;
	struct buffer_head *hashlink;
	struct list_head dirtylink;
	struct list_head lrulink; /* used for LRU list and the free list */
	unsigned count, state; // should be atomic_t
	block_t index;
	void *data;
};

struct list_head dirty_buffers;
extern unsigned dirty_buffer_count;
struct list_head journaled_buffers;
extern unsigned journaled_count;

void show_buffer(struct buffer_head *buffer);
void show_buffers(map_t *map);
struct buffer_head *mark_buffer_dirty(struct buffer_head *buffer);
struct buffer_head *set_buffer_uptodate(struct buffer_head *buffer);
struct buffer_head *set_buffer_empty(struct buffer_head *buffer);
void brelse(struct buffer_head *buffer);
void brelse_dirty(struct buffer_head *buffer);
int write_buffer_to(struct buffer_head *buffer, block_t pos);
int write_buffer(struct buffer_head *buffer);
int read_buffer(struct buffer_head *buffer);
unsigned buffer_hash(block_t block);
struct buffer_head *peekblk(map_t *map, block_t block);
struct buffer_head *blockget(map_t *map, block_t block);
struct buffer_head *blockread(map_t *map, block_t block);
void add_buffer_journaled(struct buffer_head *buffer);
int flush_buffers(map_t *map);
void evict_buffers(map_t *map);
void init_buffers(struct dev *dev, unsigned poolsize);

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
	return buffer->state == BUFFER_STATE_EMPTY;
}

static inline int buffer_uptodate(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_STATE_CLEAN;
}

static inline int buffer_dirty(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_STATE_DIRTY;
}

static inline int buffer_journaled(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_STATE_JOURNALED;
}

map_t *new_map(struct dev *dev, struct map_ops *ops); // new_map should take inode *??? does it belong here???
void free_map(map_t *map);
#endif
