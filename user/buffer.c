#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#ifdef BUFFER_FOR_TUX3
#include "utility.h"
#else
#include "diskio.h"
#endif
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
		buffer_clean(buffer) ? "" :
		buffer->state == BUFFER_EMPTY ? "-" :
		"?");
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

void show_buffer_list(struct list_head *list)
{
	struct buffer_head *buffer;
	unsigned count = 0;
	list_for_each_entry(buffer, list, link) {
		show_buffer(buffer);
		count++;
	}
	printf("(%i)\n", count);
}

void show_dirty_buffers(map_t *map)
{
	printf("map %p dirty: ", map);
	show_buffer_list(&map->dirty);
}

void show_buffers_state(unsigned state)
{
	printf("buffers in state %u: ", state);
	show_buffer_list(buffers + state);
}

void set_buffer_state_list(struct buffer_head *buffer, unsigned state, struct list_head *list)
{
	list_move_tail(&buffer->link, list);
	buffer->state = state;
}

static inline void set_buffer_state(struct buffer_head *buffer, unsigned state)
{
	set_buffer_state_list(buffer, state, buffers + state);
}

struct buffer_head *set_buffer_dirty(struct buffer_head *buffer)
{
	set_buffer_state_list(buffer, BUFFER_DIRTY, &buffer->map->dirty);
	return buffer;
}

struct buffer_head *set_buffer_clean(struct buffer_head *buffer)
{
	assert(!buffer_clean(buffer));
	set_buffer_state(buffer, BUFFER_CLEAN);
	return buffer;
}

struct buffer_head *set_buffer_empty(struct buffer_head *buffer)
{
	assert(!buffer_empty(buffer));
	set_buffer_state(buffer, BUFFER_EMPTY);
	return buffer;
}

void blockput_free(struct buffer_head *buffer)
{
	if (bufcount(buffer) != 1) {
		warn("free block %Lx/%x still in use!", (L)bufindex(buffer), bufcount(buffer));
		blockput(buffer);
		assert(bufcount(buffer) == 0);
		return;
	}
	set_buffer_empty(buffer); // free it!!! (and need a buffer free state)
	blockput(buffer);
}

void blockput(struct buffer_head *buffer)
{
	assert(buffer != NULL);
	buftrace("Release buffer %Lx, count = %i, state = %i", (L)buffer->index, buffer->count, buffer->state);
	assert(buffer->count);
	if (!--buffer->count)
		buftrace("Free buffer %Lx", (L)buffer->index);
}

unsigned buffer_hash(block_t block)
{
	return (((block >> 32) ^ (block_t)block) * 978317583) % BUFFER_BUCKETS;
}

void insert_buffer_hash(struct buffer_head *buffer)
{
	struct hlist_head *bucket = buffer->map->hash + buffer_hash(buffer->index);
	hlist_add_head(&buffer->hashlink, bucket);
	list_add_tail(&buffer->lru, &lru_buffers);
}

void remove_buffer_hash(struct buffer_head *buffer)
{
	list_del_init(&buffer->lru);
	hlist_del_init(&buffer->hashlink);
}

void evict_buffer(struct buffer_head *buffer)
{
	buftrace("evict buffer [%Lx]", (L)buffer->index);
	assert(buffer_clean(buffer) || buffer_empty(buffer));
	assert(!buffer->count);
	remove_buffer_hash(buffer);
	buffer->map = NULL;
	set_buffer_state(buffer, BUFFER_FREED); /* insert at head, not tail? */
	buffer_count--;
}

struct buffer_head *new_buffer(map_t *map)
{
	struct buffer_head *buffer = NULL;
	int err;

	if (!list_empty(buffers + BUFFER_FREED)) {
		buffer = list_entry(buffers[BUFFER_FREED].next, struct buffer_head, link);
		goto have_buffer;
	}

	if (buffer_count >= max_buffers) {
		buftrace("try to evict buffers");
		struct buffer_head *safe, *victim;
		int count = 0;
	
		list_for_each_entry_safe(victim, safe, &lru_buffers, lru) {
			if (victim->count != 0)
				continue;
			if (buffer_clean(victim) || buffer_empty(victim)) {
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
	buffer_count++;
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
	insert_buffer_hash(buffer);
	return buffer;
}

struct buffer_head *blockread(map_t *map, block_t block)
{
	struct buffer_head *buffer = blockget(map, block);
	if (buffer && buffer_empty(buffer)) {
		buftrace("read buffer %Lx, state %i", (L)buffer->index, buffer->state);
		int err = buffer->map->io(buffer, 0);
		if (err) {
			blockput(buffer);
			return NULL; // ERR_PTR me!!!
		}
	}
	return buffer;
}

void truncate_buffers_range(map_t *map, loff_t lstart, loff_t lend)
{
	unsigned blockbits = map->dev->bits;
	unsigned blocksize = 1 << blockbits;
	block_t start = (lstart + blocksize - 1) >> blockbits;
	block_t end = lend >> blockbits;
	unsigned partial = lstart & (blocksize - 1);
	unsigned partial_size = blocksize - partial;
	unsigned i;

	assert((lend & (blocksize - 1)) == (blocksize - 1));

	for (i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		struct buffer_head *buffer;
		struct hlist_node *node, *n;
		hlist_for_each_entry_safe(buffer, node, n, bucket, hashlink) {
			/* Clear partial truncated buffer */
			if (partial && buffer->index == start - 1)
				memset(buffer->data + partial, 0, partial_size);

			if (buffer->index < start || end < buffer->index)
				continue;

			if (!buffer_empty(buffer))
				set_buffer_empty(buffer);
		}
	}
}

/* !!! only used for testing */
void invalidate_buffers(map_t *map)
{
	unsigned i;
	for (i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		struct buffer_head *buffer;
		struct hlist_node *node, *n;
		hlist_for_each_entry_safe(buffer, node, n, bucket, hashlink) {
			if (!buffer->count) {
				if (!buffer_empty(buffer))
					set_buffer_empty(buffer);
				evict_buffer(buffer);
			}
		}
	}
}

int flush_list(struct list_head *list)
{
	int err = 0;
	while (!list_empty(list)) {
		struct buffer_head *buffer = list_entry(list->next, struct buffer_head, link);
		buftrace("write buffer %Lx", (L)buffer->index);
		assert(buffer_dirty(buffer));
		if ((err = buffer->map->io(buffer, 1)))
			break;
		assert(buffer_clean(buffer));
	}
	return err;
}

int flush_buffers(map_t *map)
{
	return flush_list(&map->dirty);
}

int flush_state(unsigned state)
{
	return flush_list(buffers + state);
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
	for (int i = 0; i < BUFFER_STATES; i++) {
		head = buffers + i;
		list_for_each_entry_safe(buffer, safe, head, link) {
			if (debug_buffer) {
				if (BUFFER_DIRTY <= i)
					continue;
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
		if (BUFFER_DIRTY <= buffer->state) {
			if (!debug_buffer)
				free_buffer(buffer);
			else
				has_dirty = 1;
		}
	}
	if (has_dirty) {
		warn("dirty buffer leak, or list corruption?");
		list_for_each_entry(buffer, &lru_buffers, lru) {
			if (BUFFER_DIRTY <= buffer->state) {
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

#ifndef BUFFER_PARANOIA_DEBUG
static struct buffer_head *prealloc_heads;
static unsigned char *data_pool;

static int preallocate_buffers(unsigned bufsize)
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
	free(prealloc_heads);
buffers_allocation_failure:
	warn("Unable to pre-allocate buffers. Using on demand allocation for buffers");
	return err;
}
#endif /* !BUFFER_PARANOIA_DEBUG */

void init_buffers(struct dev *dev, unsigned poolsize, int debug)
{
	debug_buffer = debug;
	INIT_LIST_HEAD(&lru_buffers);
	for (int i = 0; i < BUFFER_STATES; i++)
		INIT_LIST_HEAD(buffers + i);

	unsigned bufsize = 1 << dev->bits;
	max_buffers = poolsize / bufsize;
	max_evict = max_buffers / 10;

	int min_buffers = 100;
	if (max_buffers < min_buffers)
		max_buffers = min_buffers;

#ifndef BUFFER_PARANOIA_DEBUG
	preallocate_buffers(bufsize);
#else
	destroy_buffers();
#endif
}

int dev_blockio(struct buffer_head *buffer, int write)
{
	struct dev *dev = buffer->map->dev;
	assert(dev->bits >= 8 && dev->fd);
	int err;
#ifdef BUFFER_FOR_TUX3
	err = blockio(write, buffer, buffer->index);
#else
	if (write)
		err = diskwrite(dev->fd, buffer->data, bufsize(buffer), buffer->index << dev->bits);
	else
		err = diskread(dev->fd, buffer->data, bufsize(buffer), buffer->index << dev->bits);
#endif
	if (!err)
		set_buffer_clean(buffer);
	return err;
}

int dev_errio(struct buffer_head *buffer, int write)
{
	assert(0);
	return -EIO;
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

	for (int i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		struct buffer_head *buffer;
		struct hlist_node *node, *n;
		hlist_for_each_entry_safe(buffer, node, n, bucket, hashlink)
			evict_buffer(buffer);
	}
	free(map);
}
