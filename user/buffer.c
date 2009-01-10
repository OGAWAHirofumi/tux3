#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "diskio.h"
#include "buffer.h"
#include "trace.h"
#include "err.h"

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

#define SECTOR_BITS 9
#define SECTOR_SIZE (1 << SECTOR_BITS)
#undef BUFFER_PARANOIA_DEBUG
typedef long long L; /* widen to suppress printf warnings on 64 bit systems */

static struct list_head buffers[BUFFER_STATES], lru_buffers;
static unsigned max_buffers = 10000, max_evict = 1000, buffer_count;

void show_buffer(struct buffer_head *buffer)
{
	printf("%Lx/%i%s ", (L)buffer->index, buffer->count,
		buffer_dirty(buffer) ? "*" :
		buffer_uptodate(buffer) ? "" :
		buffer->state == BUFFER_EMPTY ? "-" :
		"???");
}

void show_buffers_(map_t *map, int all)
{
	unsigned i;

	for (i = 0; i < BUFFER_BUCKETS; i++)
	{
		struct buffer_head *buffer = map->hash[i];

		if (!buffer)
			continue;

		printf("[%i] ", i);
		for (; buffer; buffer = buffer->hashlink)
			if (all || buffer->count)
				show_buffer(buffer);
		printf("\n");
	}
}

void show_active_buffers(map_t *map)
{
	warn("(map %p)", map);
	show_buffers_(map, 0);
}

void show_buffers(map_t *map)
{
	warn("(map %p)", map);
	show_buffers_(map, 1);
}

void show_dirty_buffers(map_t *map)
{
	struct list_head *list;
	unsigned count = 0;
	printf("map %p dirty: ", map);
	list_for_each(list, &map->dirty) {
		struct buffer_head *buffer = list_entry(list, struct buffer_head, link);
		show_buffer(buffer);
		count++;
	}
	printf("(%i)\n", count);
}

struct buffer_head *mark_buffer_dirty(struct buffer_head *buffer)
{
	buftrace("set_buffer_dirty %Lx state = %u", (L)buffer->index, buffer->state);
	if (!buffer_dirty(buffer))
		list_move_tail(&buffer->link, &buffer->map->dirty);
	buffer->state = BUFFER_DIRTY;
	return buffer;
}

struct buffer_head *set_buffer_uptodate(struct buffer_head *buffer)
{
	assert(!buffer_uptodate(buffer));
	list_move_tail(&buffer->link, buffers + BUFFER_CLEAN);
	buffer->state = BUFFER_CLEAN;
	return buffer;
}

struct buffer_head *set_buffer_empty(struct buffer_head *buffer)
{
	assert(!buffer_empty(buffer));
	list_move_tail(&buffer->link, buffers + BUFFER_EMPTY);
	buffer->state = BUFFER_EMPTY;
	return buffer;
}

void brelse(struct buffer_head *buffer)
{
	assert(buffer != NULL);
	buftrace("Release buffer %Lx, count = %i, state = %i", (L)buffer->index, buffer->count, buffer->state);
	assert(buffer->count);
	if (!--buffer->count)
		buftrace("Free buffer %Lx", (L)buffer->index);
}

void brelse_dirty(struct buffer_head *buffer)
{
	buftrace("Release dirty buffer %Lx", (L)buffer->index);
	mark_buffer_dirty(buffer);
	brelse(buffer);
}

int write_buffer(struct buffer_head *buffer)
{
	buftrace("write buffer %Lx", (L)buffer->index);
	return buffer->map->ops->blockio(buffer, 1);
}

unsigned buffer_hash(block_t block)
{
	return (((block >> 32) ^ (block_t)block) * 978317583) % BUFFER_BUCKETS;
}

static struct buffer_head *remove_buffer_hash(struct buffer_head *buffer)
{
	struct buffer_head **pbuffer = buffer->map->hash + buffer_hash(buffer->index);

	for (; *pbuffer; pbuffer = &((*pbuffer)->hashlink))
		if (*pbuffer == buffer)
			goto removed;
	assert(0); /* buffer not in hash */
removed:
	*pbuffer = buffer->hashlink;
	buffer->hashlink = NULL;
	return buffer;
}

void evict_buffer(struct buffer_head *buffer)
{
	buftrace("Evict buffer [%Lx]", (L)buffer->index);
	assert(buffer_uptodate(buffer) || buffer_empty(buffer));
        if (!remove_buffer_hash(buffer))
		warn("buffer not in hash");
	list_move(&buffer->link, buffers + BUFFER_FREED);
	buffer->state = BUFFER_FREED;
	list_del(&buffer->lru);
	buffer_count--;
}

struct buffer_head *new_buffer(map_t *map)
{
	struct buffer_head *buffer = NULL;
	int min_buffers = 100, err;

	if (max_buffers < min_buffers)
		max_buffers = min_buffers;

	if (!list_empty(buffers + BUFFER_FREED)) {
		buffer = list_entry(buffers[BUFFER_FREED].next, struct buffer_head, link);
		goto have_buffer;
	}

	if (buffer_count >= max_buffers) {
		buftrace("try to evict buffers");
		struct list_head *list, *safe;
		int count = 0;
	
		list_for_each_safe(list, safe, &lru_buffers) {
			struct buffer_head *victim = list_entry(list, struct buffer_head, lru);
			if (victim->count == 0 && buffer_uptodate(victim)) {
				evict_buffer(victim);
				if (++count == max_evict)
					break;
			}
		}

		if (!list_empty(buffers + BUFFER_FREED)) {
			buffer = list_entry(buffers[BUFFER_FREED].next, struct buffer_head, link);
			goto have_buffer;
		}
	}

	buftrace("expand buffer pool");
	if (buffer_count == max_buffers) {
		warn("Maximum buffer count exceeded (%i)", buffer_count);
		return ERR_PTR(-ERANGE);
	}
	buffer = (struct buffer_head *)malloc(sizeof(struct buffer_head));
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	*buffer = (struct buffer_head){ .link = LIST_HEAD_INIT(buffer->link) };
	if ((err = -posix_memalign((void **)&(buffer->data), SECTOR_SIZE, 1 << map->dev->bits))) {
		warn("Error: %s unable to expand buffer pool", strerror(err));
		free(buffer);
		return ERR_PTR(err);
	}
have_buffer:
	assert(!buffer->count);
	assert(buffer->state == BUFFER_FREED);
	set_buffer_empty(buffer);
	buffer->map = map;
	buffer->count++;
	return buffer;
}

int count_buffers(void)
{
	int count = 0;
	struct list_head *list, *safe;
	list_for_each_safe(list, safe, &lru_buffers) {
		struct buffer_head *buffer = list_entry(list, struct buffer_head, lru);
		if (!buffer->count)
			continue;
		trace_off("buffer %Lx has non-zero count %d", (long long)buffer->index, buffer->count);
		count++;
	}
	return count;
}

struct buffer_head *peekblk(map_t *map, block_t block)
{
	struct buffer_head **bucket = map->hash + buffer_hash(block);
	for (struct buffer_head *buffer = *bucket; buffer; buffer = buffer->hashlink)
		if (buffer->index == block) {
			buffer->count++;
			return buffer;
		}
	return NULL;
}

struct buffer_head *blockget(map_t *map, block_t block)
{
	struct buffer_head **bucket = map->hash + buffer_hash(block), *buffer;
	for (buffer = *bucket; buffer; buffer = buffer->hashlink)
		if (buffer->index == block) {
			list_move_tail(&buffer->lru, &lru_buffers);
			buffer->count++;
			return buffer;
		}
	buftrace("create buffer [%Lx]", (L)block);
	if (IS_ERR(buffer = new_buffer(map)))
		return NULL; // ERR_PTR me!!!
	buffer->index = block;
	buffer->hashlink = *bucket;
	*bucket = buffer;
	list_add_tail(&buffer->lru, &lru_buffers);
	buffer_count++;
	return buffer;
}

struct buffer_head *blockread(map_t *map, block_t block)
{
	struct buffer_head *buffer = blockget(map, block);
	if (buffer && buffer_empty(buffer)) {
		buftrace("read buffer %Lx, state %i", (L)buffer->index, buffer->state);
		int err = buffer->map->ops->blockio(buffer, 0);
		if (err) {
			warn("failed to read block %Lx (%s)", (L)block, strerror(-err));
			brelse(buffer);
			return NULL;
		}
//		set_buffer_uptodate(buffer);
	}
	return buffer;
}

/* !!! only used for testing */
void evict_buffers(map_t *map)
{
	unsigned i;
	for (i = 0; i < BUFFER_BUCKETS; i++) {
		struct buffer_head *buffer;
		for (buffer = map->hash[i]; buffer;) {
			struct buffer_head *next = buffer->hashlink;
			if (!buffer->count)
				evict_buffer(buffer);
			buffer = next;
		}
		map->hash[i] = NULL; /* all buffers have been freed in this bucket */
	}
}

/* !!! only used for testing */
int flush_buffers(map_t *map) // !!! should use lru list
{
	int err = 0;

	while (!list_empty(&map->dirty)) {
		struct list_head *entry = map->dirty.next;
		struct buffer_head *buffer = list_entry(entry, struct buffer_head, link);
		if (buffer_dirty(buffer))
			if ((err = write_buffer(buffer)))
				break;
	}
	return err;
}

#ifdef BUFFER_PARANOIA_DEBUG
static void __destroy_buffers(void)
{
	struct list_head *list = buffers + BUFFER_FREED;
	while (!list_empty(list)) {
		struct buffer_head *buffer = list_entry(list->next, struct buffer_head, link);
		list_del(buffer->link);
		free(buffer->data);
		free(buffer);
	}
	list = &lru_buffers;
	while (!list_empty(list)) {
		struct buffer_head *buffer = list_entry(list->next, struct buffer_head, lru);
		list_del(buffer->lru);
		free(buffer->data);
		free(buffer);
	}
}

static void destroy_buffers(void)
{
	atexit(__destroy_buffers);
}
#endif

int preallocate_buffers(unsigned bufsize)
{
	struct buffer_head *heads = (struct buffer_head *)malloc(max_buffers*sizeof(struct buffer_head));
	unsigned char *data_pool = NULL;
	int i, err = -ENOMEM; /* if malloc fails */

	buftrace("Pre-allocating buffers...");
	if (!heads)
		goto buffers_allocation_failure;
	buftrace("Pre-allocating data for buffers...");
	if ((err = posix_memalign((void **)&data_pool, (1 << SECTOR_BITS), max_buffers*bufsize)))
		goto data_allocation_failure;

	//memset(data_pool, 0xdd, max_buffers*bufsize); /* first time init to deadly data */
	for(i = 0; i < max_buffers; i++) {
		heads[i] = (struct buffer_head){ .data = (data_pool + i*bufsize), .state = BUFFER_FREED };
		list_add_tail(&heads[i].link, buffers + BUFFER_FREED);
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
	for (int i = 0; i < BUFFER_STATES; i++)
		INIT_LIST_HEAD(buffers + i);
#ifndef BUFFER_PARANOIA_DEBUG
	unsigned bufsize = 1 << dev->bits;
	max_buffers = poolsize / bufsize;
	max_evict = max_buffers / 10;
	preallocate_buffers(bufsize);
#endif
}

int dev_blockio(struct buffer_head *buffer, int write)
{
	warn("read [%Lx]", (L)buffer->index);
	struct dev *dev = buffer->map->dev;
	assert(dev->bits >= 8 && dev->fd);
	int err;
	if (write)
		err = diskwrite(dev->fd, buffer->data, bufsize(buffer), buffer->index << dev->bits);
	else
		err = diskread(dev->fd, buffer->data, bufsize(buffer), buffer->index << dev->bits);
	if (!err)
		set_buffer_uptodate(buffer);
	return err;
}

struct map_ops volmap_ops = { .blockio = dev_blockio };

map_t *new_map(struct dev *dev, struct map_ops *ops)
{
	map_t *map = malloc(sizeof(*map)); // error???
	*map = (map_t){ .dev = dev, .ops = ops ? ops : &volmap_ops };
	INIT_LIST_HEAD(&map->dirty);
	return map;
}

void free_map(map_t *map)
{
	assert(list_empty(&map->dirty));
	free(map);
}

#ifndef include_buffer
int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 12 };
	map_t *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	show_dirty_buffers(map);
	mark_buffer_dirty(blockget(map, 1));
	show_dirty_buffers(map);
	printf("get %p\n", blockget(map, 0));
	printf("get %p\n", blockget(map, 1));
	printf("get %p\n", blockget(map, 2));
	printf("get %p\n", blockget(map, 1));
	show_dirty_buffers(map);
	exit(0);
}
#endif
