#define _XOPEN_SOURCE 600 /* pwrite >=500(?), posix_memalign needs >= 600*/
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "diskio.h"
#include "buffer.h"
#include "trace.h"

#define buftrace trace_off

/*
 * Kernel-like buffer api
 */

/*
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

struct list_head lru_buffers;
struct list_head free_buffers;

static struct buffer *buffer_table[BUFFER_BUCKETS];
LIST_HEAD(dirty_buffers);
unsigned dirty_buffer_count;
LIST_HEAD(lru_buffers);
unsigned buffer_count;
LIST_HEAD(free_buffers);
unsigned journaled_count;
LIST_HEAD(journaled_buffers); /* bufferes that have been written to journal but not yet to snapstore */
static unsigned max_buffers = 10000;
static unsigned max_evict = 1000; /* free 10 percent of the buffers */

void show_buffer(struct buffer *buffer)
{
	warn("%s%Lx/%i ", // !!! fixme, need a warntext that doesn't print eol
		buffer_dirty(buffer)? "+": buffer_uptodate(buffer)? "": buffer->state == BUFFER_STATE_EMPTY? "?": "x",
		buffer->block, buffer->count);
}

void show_buffers_(int all)
{
	unsigned i;

	for (i = 0; i < BUFFER_BUCKETS; i++)
	{
		struct buffer *buffer = buffer_table[i];

		if (!buffer)
			continue;

		warn("[%i] ", i);
		for (; buffer; buffer = buffer->hashlist)
			if (all || buffer->count)
				show_buffer(buffer);
		warn("");
	}
}

void show_active_buffers(void)
{
	warn("Active buffers:");
	show_buffers_(0);
}

void show_buffers(void)
{
	warn("Buffers:");
	show_buffers_(1);
}

void show_dirty_buffers(void)
{
	struct list_head *list;

	warn("%i dirty buffers: ", dirty_buffer_count);
	list_for_each(list, &dirty_buffers) {
		struct buffer *buffer = list_entry(list, struct buffer, dirty_list);
		show_buffer(buffer);
	}
	warn("");
}

void show_journaled_buffers(void)
{
	struct list_head *list;
	warn("%i journaled buffers: ", journaled_count);
	list_for_each(list, &journaled_buffers) {
		struct buffer *buffer = list_entry(list, struct buffer, dirty_list);
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
		list_del(&buffer->dirty_list);
		dirty_buffer_count--;
	}
	buffer->state = BUFFER_STATE_JOURNALED;
	list_add_tail(&buffer->dirty_list, &journaled_buffers);
	journaled_count ++;
}

static void remove_buffer_journaled(struct buffer *buffer)
{
	list_del(&buffer->dirty_list);
	journaled_count --;
}

void set_buffer_dirty(struct buffer *buffer)
{
	buftrace(warn("set_buffer_dirty %Lx state=%u", buffer->block, buffer->state););
	if (buffer_dirty(buffer))
		return;
	if (buffer_journaled(buffer))
		remove_buffer_journaled(buffer);
	assert(!buffer->dirty_list.next);
	assert(!buffer->dirty_list.prev);
	list_add_tail(&buffer->dirty_list, &dirty_buffers);
	buffer->state = BUFFER_STATE_DIRTY;
	dirty_buffer_count++;
}

void set_buffer_uptodate(struct buffer *buffer)
{
	if (buffer_dirty(buffer)) {
		list_del(&buffer->dirty_list);
		dirty_buffer_count--;
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
	buftrace(warn("Release buffer %Lx, count = %i", buffer->block, buffer->count););
	assert(buffer->count);
	if (!--buffer->count)
		trace_off(warn("Free buffer %Lx", buffer->block));
}

void brelse_dirty(struct buffer *buffer)
{
	buftrace(warn("Release dirty buffer %Lx", buffer->block););
	set_buffer_dirty(buffer);
	brelse(buffer);
}

int write_buffer_to(struct buffer *buffer, sector_t block)
{
	return diskwrite(buffer->dev->fd, buffer->data, buffer_size(buffer), block << buffer->dev->blockbits);
}

int write_buffer(struct buffer *buffer)
{
	buftrace(warn("write buffer %Lx", buffer->block););
	int err = write_buffer_to(buffer, buffer->block);
	if (!err)
		set_buffer_uptodate(buffer);
	return err;
}

unsigned buffer_hash(sector_t block)
{
	return (((block >> 32) ^ (sector_t)block) * 978317583) % BUFFER_BUCKETS;
}

static void add_buffer_lru(struct buffer *buffer)
{
	buffer_count++;
	list_add_tail(&buffer->list, &lru_buffers);
}

static void remove_buffer_lru(struct buffer *buffer)
{
	buffer_count--;
	list_del(&buffer->list);
}

static struct buffer *remove_buffer_hash(struct buffer *buffer)
{
	struct buffer **pbuffer = buffer_table + buffer_hash(buffer->block);

	for (; *pbuffer; pbuffer = &((*pbuffer)->hashlist))
		if (*pbuffer == buffer)
			goto removed;
	assert(0); /* buffer not in hash */
removed:
	*pbuffer = buffer->hashlist;
	buffer->hashlist = NULL;
	return buffer;
}

static void add_buffer_free(struct buffer *buffer)
{
	assert(buffer->state == BUFFER_STATE_CLEAN || buffer->state == BUFFER_STATE_EMPTY);
	buffer->state = BUFFER_STATE_EMPTY;
	list_add_tail(&buffer->list, &free_buffers);
}

static struct buffer *remove_buffer_free(void)
{
	struct buffer *buffer = NULL;
	if (!list_empty(&free_buffers)) {
		buffer = list_entry(free_buffers.next, struct buffer, list);
		list_del(&buffer->list);
	}
	return buffer;
}

#define SECTOR_BITS 9
#define SECTOR_SIZE (1 << SECTOR_BITS)

struct buffer *new_buffer(struct dev *dev, sector_t block)
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
		struct buffer *buffer_evict = list_entry(list, struct buffer, list);
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
		warn("Maximum buffer count exceeded (%i)", dirty_buffer_count);
		return NULL;
	}
	buffer = (struct buffer *)malloc(sizeof(struct buffer));
	if (!buffer)
		return NULL;
	*buffer = (struct buffer){ .state = BUFFER_STATE_EMPTY };
	if ((err = posix_memalign((void **)&(buffer->data), SECTOR_SIZE, buffer_size(buffer)))) {
		warn("Error: %s unable to expand buffer pool", strerror(err));
		free(buffer);
		return NULL;
	}

have_buffer:
	assert(!buffer->count);
	assert(buffer->state == BUFFER_STATE_EMPTY);
	buffer->dev = dev;
	buffer->block = block;
	buffer->count++;
	add_buffer_lru(buffer);
	return buffer;
}

int count_buffer(void)
{
        struct list_head *list, *safe;
        int count = 0;
        list_for_each_safe(list, safe, &lru_buffers) {
                struct buffer *buffer = list_entry(list, struct buffer, list);	
		if (!buffer->count)
			continue;
		trace_off(warn("buffer %Lx has non-zero count %d", (long long)buffer->block, buffer->count););
		count++;
	}
	return count;
}

struct buffer *getblk(struct dev *dev, sector_t block)
{
	struct buffer **bucket = buffer_table + buffer_hash(block), *buffer;

	for (buffer = *bucket; buffer; buffer = buffer->hashlist)
		if (buffer->block == block) {
			buftrace(warn("Found buffer for %Lx", block););
			buffer->count++;
			list_del(&buffer->list);
			list_add_tail(&buffer->list, &lru_buffers);
			return buffer;
		}
	if (!(buffer = new_buffer(dev, block)))
		return NULL;
	buffer->dev = dev;
	buffer->hashlist = *bucket;
	*bucket = buffer;
	return buffer;
}

struct buffer *bread(struct dev *dev, sector_t block)
{
	int err = 0;
	struct buffer *buffer;

	if (!(buffer = getblk(dev, block)))
		return NULL;
	if (buffer->state != BUFFER_STATE_EMPTY)
		return buffer;
	buftrace(warn("read buffer %Lx", buffer->block););
printf(">>> dev fd = %i\n", buffer->dev->fd);
	if ((err = diskread(buffer->dev->fd, buffer->data, buffer_size(buffer), buffer->block << dev->blockbits))) {
		warn("failed to read block %Lx (%s)", block, strerror(-err));
		brelse(buffer);
		return NULL;
	}
	set_buffer_uptodate(buffer);
	return buffer;
}

void evict_buffer(struct buffer *buffer)
{
	remove_buffer_lru(buffer);
        if (!remove_buffer_hash(buffer))
		warn("buffer not found in hashlist");
	buftrace(warn("Evicted buffer for %Lx", buffer->block););
	add_buffer_free(buffer);
}

/* !!! only used for testing */
void evict_buffers(void)
{
	unsigned i;
	for (i = 0; i < BUFFER_BUCKETS; i++)
	{
		struct buffer *buffer;
		for (buffer = buffer_table[i]; buffer;) {
			struct buffer *next = buffer->hashlist;
			if (!buffer->count)
				evict_buffer(buffer);
			buffer = next;
		}
		buffer_table[i] = NULL; /* all buffers have been freed in this bucket */
	}
}

/* !!! only used for testing */
int flush_buffers(void) // !!! should use lru list
{
	int err = 0;

	while (!list_empty(&dirty_buffers)) {
		struct list_head *entry = dirty_buffers.next;
		struct buffer *buffer = list_entry(entry, struct buffer, dirty_list);
		if (buffer_dirty(buffer))
			if ((err = write_buffer(buffer)) != 0)
				break;
	}
	if (err != 0)
		error("Flush buffers failed with %s", strerror(-err));
	return(err);
}

int preallocate_buffers(unsigned bufsize) {
	struct buffer *buffers = (struct buffer *)malloc(max_buffers*sizeof(struct buffer));
	unsigned char *data_pool = NULL;
	int i, error = -ENOMEM; /* if malloc fails */

	buftrace(warn("Pre-allocating buffers..."););
	if (!buffers)
		goto buffers_allocation_failure;
	buftrace(warn("Pre-allocating data for buffers..."););
	if ((error = posix_memalign((void **)&data_pool, (1 << SECTOR_BITS), max_buffers*bufsize)))
		goto data_allocation_failure;

	/* let's clear out the buffer array and data and set to deadly data 0xdd */
	memset(data_pool, 0xdd, max_buffers*bufsize);

	for(i = 0; i < max_buffers; i++) {
		buffers[i] = (struct buffer){ .data = (data_pool + i*bufsize), .state = BUFFER_STATE_EMPTY };
		add_buffer_free(&buffers[i]);
	}

	return 0; /* sucess on pre-allocation of buffers */

data_allocation_failure:
	/* go back to on demand allocation */
	warn("Error: %s unable to allocate space for buffer data", strerror(error));
	free(buffers);
buffers_allocation_failure:
	warn("Unable to pre-allocate buffers. Using on demand allocation for buffers");
	return error;
}

/* mem_pool_size defines "roughly" the amount of memory allocated for
 * buffers. I use the term "roughly" since it doesn't take into
 * consideration the size of the buffer struct and the overhead for
 * posix_memalign(). From empirical tests, the additional memory
 * is negligible.
 */

void init_buffers(unsigned bufsize, unsigned mem_pool_size)
{
	assert(bufsize);
	memset(buffer_table, 0, sizeof(buffer_table));
	INIT_LIST_HEAD(&dirty_buffers);
	dirty_buffer_count = 0;
	INIT_LIST_HEAD(&lru_buffers);
	buffer_count = 0;
	INIT_LIST_HEAD(&free_buffers);
	journaled_count = 0;
	INIT_LIST_HEAD(&journaled_buffers);

	/* calculate number of max buffers to a fixed size, independent of chunk size */
	max_buffers = mem_pool_size / bufsize;
	max_evict = max_buffers / 10;

	preallocate_buffers(bufsize);
}
