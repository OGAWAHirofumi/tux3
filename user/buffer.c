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
#define BUFFER_PARANOIA_DEBUG
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
	struct buffer_head *buffer;
	struct hlist_node *node;
	unsigned i;

	for (i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		if (hlist_empty(bucket))
			continue;

		printf("[%i] ", i);
		hlist_for_each_entry(buffer, node, bucket, hashlink) {
			if (all || buffer->count)
				show_buffer(buffer);
		}
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
	struct buffer_head *buffer;
	unsigned count = 0;
	printf("map %p dirty: ", map);
	list_for_each_entry(buffer, &map->dirty, link) {
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
	return buffer->map->io(buffer, 1);
}

unsigned buffer_hash(block_t block)
{
	return (((block >> 32) ^ (block_t)block) * 978317583) % BUFFER_BUCKETS;
}

static struct buffer_head *remove_buffer_hash(struct buffer_head *buffer)
{
//	assert(!hlist_unhashed(&buffer->hashlink));  /* buffer not in hash */
#ifdef BUFFER_PARANOIA_DEBUG
	hlist_del_init(&buffer->hashlink);
#else
	hlist_del(&buffer->hashlink);
#endif
	return buffer;
}

void evict_buffer(struct buffer_head *buffer)
{
	buftrace("evict buffer [%Lx]", (L)buffer->index);
	assert(buffer_uptodate(buffer) || buffer_empty(buffer));
        if (!remove_buffer_hash(buffer))
		warn("buffer not in hash");
	list_move(&buffer->link, buffers + BUFFER_FREED);
	buffer->state = BUFFER_FREED;
#ifdef BUFFER_PARANOIA_DEBUG
	list_del_init(&buffer->lru);
#else
	list_del(&buffer->lru);
#endif
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
		struct buffer_head *safe, *victim;
		int count = 0;
	
		list_for_each_entry_safe(victim, safe, &lru_buffers, lru) {
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
	*buffer = (struct buffer_head){
		.link = LIST_HEAD_INIT(buffer->link),
		.lru = LIST_HEAD_INIT(buffer->lru),
	};
	INIT_HLIST_NODE(&buffer->hashlink);
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
	struct buffer_head *safe, *buffer;
	int count = 0;
	list_for_each_entry_safe(buffer, safe, &lru_buffers, lru) {
		if (!buffer->count)
			continue;
		trace_off("buffer %Lx has non-zero count %d", (long long)buffer->index, buffer->count);
		count++;
	}
	return count;
}

struct buffer_head *peekblk(map_t *map, block_t block)
{
	struct hlist_head *bucket = map->hash + buffer_hash(block);
	struct buffer_head *buffer;
	struct hlist_node *node;
	hlist_for_each_entry(buffer, node, bucket, hashlink)
		if (buffer->index == block) {
			buffer->count++;
			return buffer;
		}
	return NULL;
}

struct buffer_head *blockget(map_t *map, block_t block)
{
	struct hlist_head *bucket = map->hash + buffer_hash(block);
	struct buffer_head *buffer;
	struct hlist_node *node;
	hlist_for_each_entry(buffer, node, bucket, hashlink)
		if (buffer->index == block) {
			list_move_tail(&buffer->lru, &lru_buffers);
			buffer->count++;
			return buffer;
		}
	buftrace("make buffer [%Lx]", (L)block);
	if (IS_ERR(buffer = new_buffer(map)))
		return NULL; // ERR_PTR me!!!
	buffer->index = block;
	hlist_add_head(&buffer->hashlink, bucket);
	list_add_tail(&buffer->lru, &lru_buffers);
	buffer_count++;
	return buffer;
}

struct buffer_head *blockread(map_t *map, block_t block)
{
	struct buffer_head *buffer = blockget(map, block);
	if (buffer && buffer_empty(buffer)) {
		buftrace("read buffer %Lx, state %i", (L)buffer->index, buffer->state);
		int err = buffer->map->io(buffer, 0);
		if (err) {
			brelse(buffer);
			return NULL; // ERR_PTR me!!!
		}
	}
	return buffer;
}

int blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
	unsigned oldstate = buffer->state;
	assert(oldstate < BUFFER_STATES);
	newdelta &= BUFFER_DIRTY_STATES - 1;
	if (oldstate >= BUFFER_DIRTY) {
		if (oldstate - BUFFER_DIRTY == newdelta)
			return 0;
		buftrace("fork buffer %p", buffer);
		struct buffer_head *clone = new_buffer(buffer->map);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);
		void *data = buffer->data;
		buffer->data = clone->data;
		clone->data = data;
		list_move(&clone->link, buffers + oldstate);
		clone->state = oldstate;
		brelse(clone);
	}
	list_move(&buffer->link, &buffer->map->dirty);
	buffer->state = BUFFER_DIRTY + newdelta;
	return 0;
}

/* !!! only used for testing */
void evict_buffers(map_t *map)
{
	unsigned i;
	for (i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		struct buffer_head *buffer;
		struct hlist_node *node, *n;
		hlist_for_each_entry_safe(buffer, node, n, bucket, hashlink) {
			if (!buffer->count)
				evict_buffer(buffer);
		}
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

static int debug_buffer;

#ifdef BUFFER_PARANOIA_DEBUG
static void free_buffer(struct buffer_head *buffer)
{
	if (list_empty(&buffer->lru))
		assert(hlist_unhashed(&buffer->hashlink));
	else
		assert(!hlist_unhashed(&buffer->hashlink));
	list_del(&buffer->lru);
	list_del(&buffer->link);
	free(buffer->data);
	free(buffer);
}

static void __destroy_buffers(void)
{
	struct buffer_head *buffer, *safe;
	struct list_head *head;
	for (int i = 0; i < BUFFER_DIRTY; i++) {
		head = buffers + i;
		list_for_each_entry_safe(buffer, safe, head, link) {
			if (debug_buffer) {
				if (buffer->count || i != buffer->state)
					continue;
			}
			free_buffer(buffer);
		}
		if (!list_empty(head)) {
			warn("state %d: buffer leak, or list corruption?", i);
			list_for_each_entry(buffer, head, link) {
				printf("map [%p] ", buffer->map);
				show_buffer(buffer);
			}
			printf("\n");
		}
		assert(list_empty(head));
	}
#if 1
	int has_dirty = 0;
	list_for_each_entry_safe(buffer, safe, &lru_buffers, lru) {
		if (buffer_dirty(buffer)) {
			if (!debug_buffer)
				free_buffer(buffer);
			else
				has_dirty = 1;
		}
	}
	if (has_dirty) {
		warn("dirty buffer leak, or list corruption?");
		list_for_each_entry(buffer, &lru_buffers, lru) {
			if (buffer_dirty(buffer)) {
				printf("map [%p] ", buffer->map);
				show_buffer(buffer);
			}
		}
		printf("\n");
		assert(list_empty(&lru_buffers));
	}
#else
	assert(list_empty(&lru_buffers));
#endif
}

static void destroy_buffers(void)
{
	atexit(__destroy_buffers);
}
#endif

struct buffer_head *prealloc_heads;
static unsigned char *data_pool;

int preallocate_buffers(unsigned bufsize)
{
	int i, err = -ENOMEM; /* if malloc fails */

	buftrace("Pre-allocating buffers...");
	prealloc_heads = malloc(max_buffers * sizeof(*prealloc_heads));
	if (!prealloc_heads)
		goto buffers_allocation_failure;
	buftrace("Pre-allocating data for buffers...");
	if ((err = posix_memalign((void **)&data_pool, (1 << SECTOR_BITS), max_buffers*bufsize)))
		goto data_allocation_failure;

	//memset(data_pool, 0xdd, max_buffers*bufsize); /* first time init to deadly data */
	for(i = 0; i < max_buffers; i++) {
		prealloc_heads[i] = (struct buffer_head){
			.data = (data_pool + i*bufsize),
			.state = BUFFER_FREED,
			.lru = LIST_HEAD_INIT(prealloc_heads[i].lru),
		};
		INIT_HLIST_NODE(&prealloc_heads[i].hashlink);
		list_add_tail(&prealloc_heads[i].link, buffers + BUFFER_FREED);
	}

	return 0; /* sucess on pre-allocation of buffers */

data_allocation_failure:
	warn("Error: %s unable to allocate space for buffer data", strerror(err));
	free(buffers);
buffers_allocation_failure:
	warn("Unable to pre-allocate buffers. Using on demand allocation for buffers");
	return err;
}

void init_buffers(struct dev *dev, unsigned poolsize, int debug)
{
	debug_buffer = debug;
	INIT_LIST_HEAD(&lru_buffers);
	for (int i = 0; i < BUFFER_STATES; i++)
		INIT_LIST_HEAD(buffers + i);
#ifndef BUFFER_PARANOIA_DEBUG
	unsigned bufsize = 1 << dev->bits;
	max_buffers = poolsize / bufsize;
	max_evict = max_buffers / 10;
	preallocate_buffers(bufsize);
#else
	destroy_buffers();
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

map_t *new_map(struct dev *dev, blockio_t *io)
{
	map_t *map = malloc(sizeof(*map)); // error???
	*map = (map_t){ .dev = dev, .io = io ? io : dev_blockio };
	INIT_LIST_HEAD(&map->dirty);
	for (int i = 0; i < BUFFER_BUCKETS; i++)
		INIT_HLIST_HEAD(&map->hash[i]);
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
	init_buffers(dev, 1 << 20, 0);
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
