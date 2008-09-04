#define _XOPEN_SOURCE 600 /* pwrite >=500(?), posix_memalign needs >= 600*/
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "diskio.h"
#include "buffer.h"
#include "trace.h"

#define buftrace trace_off

/*
 * Emulate kernel buffers in userspace
 *
 * Even though we are in user space, for reasons of durability and speed
 * we need to access the block directly, handle our own block caching and
 * keep track block by block of which parts of the on-disk data structures
 * as they are accessed and modified.  There's no need to reinvent the
 * wheel here.  I have basically cloned the traditional Unix kernel buffer
 * paradigm, with one small twist of my own, that is, instead of state
 * bits we use scalar values.  This captures the notion of buffer state
 * transitions more precisely than the traditional approach.
 *
 * One big benefit of using a buffer paradigm that looks and acts very
 * much like the kernel incarnation is, porting this into the kernel is
 * going to be a whole lot easier.  Most higher level code will not need
 * to be modified at all.  Another benefit is, it will be much easier to
 * add async IO.
 */

struct list_head free_buffers;
struct list_head lru_buffers;
unsigned buffer_count;
struct list_head journaled_buffers;
unsigned journaled_count;

static unsigned max_buffers = 10000;
static unsigned max_evict = 1000; /* free 10 percent of the buffers */

void show_buffer(struct buffer *buffer)
{
	printf("%Lx/%i%s ", buffer->index, buffer->count,
		buffer_dirty(buffer) ? "*" :
		buffer_uptodate(buffer) ? "" :
		buffer->state == BUFFER_STATE_EMPTY ? "-" :
		"???");
}

void show_buffers_(struct map *map, int all)
{
	unsigned i;

	for (i = 0; i < BUFFER_BUCKETS; i++)
	{
		struct buffer *buffer = map->hash[i];

		if (!buffer)
			continue;

		printf("[%i] ", i);
		for (; buffer; buffer = buffer->hashlink)
			if (all || buffer->count)
				show_buffer(buffer);
		printf("\n");
	}
}

void show_active_buffers(struct map *map)
{
	warn("(map %p)", map);
	show_buffers_(map, 0);
}

void show_buffers(struct map *map)
{
	warn("(map %p)", map);
	show_buffers_(map, 1);
}

void show_dirty_buffers(struct map *map)
{
	struct list_head *list;

	warn("%i dirty buffers: ", map->dirty_count);
	list_for_each(list, &map->dirty) {
		struct buffer *buffer = list_entry(list, struct buffer, dirtylink);
		show_buffer(buffer);
	}
	warn("");
}

void show_journaled_buffers(void)
{
	struct list_head *list;
	warn("%i journaled buffers: ", journaled_count);
	list_for_each(list, &journaled_buffers) {
		struct buffer *buffer = list_entry(list, struct buffer, dirtylink);
		show_buffer(buffer);
	}
	warn("");
}

#if 0
void dump_buffer(struct buffer *buffer, unsigned offset, unsigned length)
{
	hexdump(buffer->data + offset, length);
}
#endif

void add_buffer_journaled(struct buffer *buffer)
{
	if (buffer_dirty(buffer)) {
		list_del(&buffer->dirtylink);
		buffer->map->dirty_count--;
	}
	buffer->state = BUFFER_STATE_JOURNALED;
	list_add_tail(&buffer->dirtylink, &journaled_buffers);
	journaled_count ++;
}

static void remove_buffer_journaled(struct buffer *buffer)
{
	list_del(&buffer->dirtylink);
	journaled_count --;
}

void set_buffer_dirty(struct buffer *buffer)
{
	buftrace(warn("set_buffer_dirty %Lx state=%u", buffer->index, buffer->state););
	if (buffer_dirty(buffer))
		return;
	if (buffer_journaled(buffer))
		remove_buffer_journaled(buffer);
	assert(!buffer->dirtylink.next);
	assert(!buffer->dirtylink.prev);
	list_add_tail(&buffer->dirtylink, &buffer->map->dirty);
	buffer->state = BUFFER_STATE_DIRTY;
	buffer->map->dirty_count++;
}

void set_buffer_uptodate(struct buffer *buffer)
{
	if (buffer_dirty(buffer)) {
		list_del(&buffer->dirtylink);
		buffer->map->dirty_count--;
	}
	if (buffer_journaled(buffer))
		remove_buffer_journaled(buffer);
	buffer->state = BUFFER_STATE_CLEAN;
}

void set_buffer_empty(struct buffer *buffer)
{
	set_buffer_uptodate(buffer); // to remove from dirty list
	buffer->state = BUFFER_STATE_EMPTY;
}

void brelse(struct buffer *buffer)
{
	buftrace(warn("Release buffer %Lx, count = %i, state = %i", buffer->index, buffer->count, buffer->state););
	assert(buffer->count);
	if (!--buffer->count)
		trace_off(warn("Free buffer %Lx", buffer->index));
}

void brelse_dirty(struct buffer *buffer)
{
	buftrace(warn("Release dirty buffer %Lx", buffer->index););
	set_buffer_dirty(buffer);
	brelse(buffer);
}

int write_buffer_to(struct buffer *buffer, sector_t block)
{
	return (buffer->map->ops->blockio)(buffer, 1);
}

int write_buffer(struct buffer *buffer)
{
	buftrace(warn("write buffer %Lx", buffer->index););
	set_buffer_uptodate(buffer);
	int err = write_buffer_to(buffer, buffer->index);
	if (err)
		set_buffer_dirty(buffer);
	return err;
}

unsigned buffer_hash(sector_t block)
{
	return (((block >> 32) ^ (sector_t)block) * 978317583) % BUFFER_BUCKETS;
}

static void add_buffer_lru(struct buffer *buffer)
{
	buffer_count++;
	list_add_tail(&buffer->lrulink, &lru_buffers);
}

static void remove_buffer_lru(struct buffer *buffer)
{
	buffer_count--;
	list_del(&buffer->lrulink);
}

static struct buffer *remove_buffer_hash(struct buffer *buffer)
{
	struct buffer **pbuffer = buffer->map->hash + buffer_hash(buffer->index);

	for (; *pbuffer; pbuffer = &((*pbuffer)->hashlink))
		if (*pbuffer == buffer)
			goto removed;
	assert(0); /* buffer not in hash */
removed:
	*pbuffer = buffer->hashlink;
	buffer->hashlink = NULL;
	return buffer;
}

static void add_buffer_free(struct buffer *buffer)
{
	assert(buffer_uptodate(buffer) || buffer_empty(buffer));
	buffer->state = BUFFER_STATE_EMPTY;
	list_add_tail(&buffer->lrulink, &free_buffers);
}

static struct buffer *remove_buffer_free(void)
{
	struct buffer *buffer = NULL;
	if (!list_empty(&free_buffers)) {
		buffer = list_entry(free_buffers.next, struct buffer, lrulink);
		list_del(&buffer->lrulink);
	}
	return buffer;
}

#define SECTOR_BITS 9
#define SECTOR_SIZE (1 << SECTOR_BITS)

struct buffer *new_buffer(struct map *map, sector_t block)
{
	buftrace(printf("Allocate buffer, block = %Lx\n", block);)
	struct buffer *buffer = NULL;
	int min_buffers = 100, err;

	if (max_buffers < min_buffers)
		max_buffers = min_buffers;

	/* check if we hit the MAX_BUFFER limit and if there are any free buffers avail */
	if ((buffer = remove_buffer_free()))
		goto have_buffer;

	if (buffer_count < max_buffers)
		goto alloc_buffer;

	buftrace(printf("try to evict buffers\n");)
	struct list_head *list, *safe;
	int count = 0;

	list_for_each_safe(list, safe, &lru_buffers) {
		struct buffer *buffer_evict = list_entry(list, struct buffer, lrulink);
		if (buffer_evict->count == 0 && !buffer_dirty(buffer_evict) && !buffer_journaled(buffer_evict)) {
			remove_buffer_lru(buffer_evict);
			remove_buffer_hash(buffer_evict);
			add_buffer_free(buffer_evict);
			if (++count == max_evict)
				break;
		}
	}
	if ((buffer = remove_buffer_free()))
		goto have_buffer;

alloc_buffer:
	buftrace(warn("expand buffer pool");)
	if (buffer_count == max_buffers) {
		warn("Maximum buffer count exceeded (%i)", buffer_count);
		return NULL;
	}
	buffer = (struct buffer *)malloc(sizeof(struct buffer));
	if (!buffer)
		return NULL;
	*buffer = (struct buffer){ .state = BUFFER_STATE_EMPTY };
	if ((err = posix_memalign((void **)&(buffer->data), SECTOR_SIZE, bufsize(buffer)))) {
		warn("Error: %s unable to expand buffer pool", strerror(err));
		free(buffer);
		return NULL;
	}

have_buffer:
	assert(!buffer->count);
	assert(buffer_empty(buffer));
	buffer->map = map;
	buffer->index = block;
	buffer->count++;
	add_buffer_lru(buffer);
	return buffer;
}

int count_buffers(void)
{
        int count = 0;
        struct list_head *list, *safe;
        list_for_each_safe(list, safe, &lru_buffers) {
                struct buffer *buffer = list_entry(list, struct buffer, lrulink);	
		if (!buffer->count)
			continue;
		trace_off(warn("buffer %Lx has non-zero count %d", (long long)buffer->index, buffer->count););
		count++;
	}
	return count;
}

struct buffer *getblk(struct map *map, sector_t block)
{
	struct buffer **bucket = map->hash + buffer_hash(block), *buffer;

	for (buffer = *bucket; buffer; buffer = buffer->hashlink)
		if (buffer->index == block) {
			buftrace(warn("Found buffer for %Lx, state %i", block, buffer->state););
			buffer->count++;
			list_del(&buffer->lrulink);
			list_add_tail(&buffer->lrulink, &lru_buffers);
			return buffer;
		}
	if (!(buffer = new_buffer(map, block)))
		return NULL;
	buffer->hashlink = *bucket;
	*bucket = buffer;
	return buffer;
}

struct buffer *bread(struct map *map, sector_t block)
{
	struct buffer *buffer = getblk(map, block);
	if (buffer && buffer_empty(buffer)) {
		buftrace(warn("read buffer %Lx, state %i", buffer->index, buffer->state););
		int err = buffer->map->ops->blockio(buffer, 0);
		if (err) {
			warn("failed to read block %Lx (%s)", block, strerror(-err));
			brelse(buffer);
			return NULL;
		}
		set_buffer_uptodate(buffer);
	}
	return buffer;
}

void evict_buffer(struct buffer *buffer)
{
	remove_buffer_lru(buffer);
        if (!remove_buffer_hash(buffer))
		warn("buffer not found in hashlist");
	buftrace(warn("Evicted buffer for %Lx", buffer->index););
	add_buffer_free(buffer);
}

/* !!! only used for testing */
void evict_buffers(struct map *map)
{
	unsigned i;
	for (i = 0; i < BUFFER_BUCKETS; i++)
	{
		struct buffer *buffer;
		for (buffer = map->hash[i]; buffer;) {
			struct buffer *next = buffer->hashlink;
			if (!buffer->count)
				evict_buffer(buffer);
			buffer = next;
		}
		map->hash[i] = NULL; /* all buffers have been freed in this bucket */
	}
}

/* !!! only used for testing */
int flush_buffers(struct map *map) // !!! should use lru list
{
	int err = 0;

	while (!list_empty(&map->dirty)) {
		struct list_head *entry = map->dirty.next;
		struct buffer *buffer = list_entry(entry, struct buffer, dirtylink);
		if (buffer_dirty(buffer))
			if ((err = write_buffer(buffer)))
				break;
	}
	return err;
}

int preallocate_buffers(unsigned bufsize) {
	struct buffer *buffers = (struct buffer *)malloc(max_buffers*sizeof(struct buffer));
	unsigned char *data_pool = NULL;
	int i, err = -ENOMEM; /* if malloc fails */

	buftrace(warn("Pre-allocating buffers..."););
	if (!buffers)
		goto buffers_allocation_failure;
	buftrace(warn("Pre-allocating data for buffers..."););
	if ((err = posix_memalign((void **)&data_pool, (1 << SECTOR_BITS), max_buffers*bufsize)))
		goto data_allocation_failure;

	/* let's clear out the buffer array and data and set to deadly data 0xdd */
	memset(data_pool, 0xdd, max_buffers*bufsize);

	for(i = 0; i < max_buffers; i++) {
		buffers[i] = (struct buffer){ .data = (data_pool + i*bufsize), .state = BUFFER_STATE_EMPTY };
		add_buffer_free(&buffers[i]);
	}

	return 0; /* sucess on pre-allocation of buffers */

data_allocation_failure:
	warn("Error: %s unable to allocate space for buffer data", strerror(err));
	free(buffers);
buffers_allocation_failure:
	warn("Unable to pre-allocate buffers. Using on demand allocation for buffers");
	return err;
}

void init_buffers(struct dev *dev, unsigned poolsize)
{
	INIT_LIST_HEAD(&lru_buffers);
	INIT_LIST_HEAD(&free_buffers);
	INIT_LIST_HEAD(&journaled_buffers);

	unsigned bufsize = 1 << dev->bits;
	max_buffers = poolsize / bufsize;
	max_evict = max_buffers / 10;
	preallocate_buffers(bufsize);
}

int devmap_blockio(struct buffer *buffer, int write)
{
	warn("%s [%Lx]", write ? "write" : "read", (long long)buffer->index);
	struct dev *dev = buffer->map->dev;
	assert(dev->bits >= 8 && dev->fd);
	return (write ? diskwrite : diskread)
		(dev->fd, buffer->data, bufsize(buffer), buffer->index << dev->bits);
}

struct map_ops devmap_ops = { .blockio = devmap_blockio };

struct map *new_map(struct dev *dev, struct map_ops *ops)
{
	struct map *map = malloc(sizeof(*map)); // error???
	*map = (struct map){ .dev = dev, .ops = ops ? ops : &devmap_ops };
	INIT_LIST_HEAD(&map->dirty);
	return map;
}

void free_map(struct map *map)
{
	assert(list_empty(&map->dirty));
	free(map);
}

int buffer_main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 12 };
	struct map *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	show_dirty_buffers(map);
	set_buffer_dirty(getblk(map, 1));
	show_dirty_buffers(map);
	printf("get %p\n", getblk(map, 0));
	printf("get %p\n", getblk(map, 1));
	printf("get %p\n", getblk(map, 2));
	printf("get %p\n", getblk(map, 1));
	return 0;
}
