#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#ifndef BUFFER_FOR_TUX3
#include "diskio.h"
#endif
#include "buffer.h"
#include "trace.h"
#include "libklib/err.h"
#include "libklib/list_sort.h"

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

#define MIN_SECTOR_BITS		6
#define SECTOR_BITS		9
#define SECTOR_SIZE		(1 << SECTOR_BITS)

#define BUFFER_PARANOIA_DEBUG
/*
 * 0 - no debug
 * 1 - leak check
 * 2 - "1" and reclaim buffer early
 */
static int debug_buffer;

static struct list_head buffers[BUFFER_STATES], lru_buffers;
static unsigned max_buffers = 10000, max_evict = 1000, buffer_count;

void show_buffer(struct buffer_head *buffer)
{
	printf("%Lx/%i%s ", buffer->index, buffer->count,
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
			if (all || buffer->count >= !hlist_unhashed(&buffer->hashlink) + 1)
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
	for (int i = 0; i < BUFFER_DIRTY_STATES; i++) {
		printf("map %p dirty [%d]: ", map, i);
		show_buffer_list(dirty_head_when(&map->dirty, i));
	}
}

void show_buffers_state(unsigned state)
{
	printf("buffers in state %u: ", state);
	show_buffer_list(buffers + state);
}

int count_buffers(void)
{
	struct buffer_head *safe, *buffer;
	int count = 0;
	list_for_each_entry_safe(buffer, safe, &lru_buffers, lru) {
		if (buffer->count <= !hlist_unhashed(&buffer->hashlink))
			continue;
		trace_off("buffer %Lx has non-zero count %d", (long long)buffer->index, buffer->count);
		count++;
	}
	return count;
}

static int reclaim_buffer(struct buffer_head *buffer)
{
	/* If buffer is not dirty and ->count == 1, we can reclaim buffer */
	if (buffer->count == 1 && !buffer_dirty(buffer)) {
		if (!hlist_unhashed(&buffer->hashlink)) {
			remove_buffer_hash(buffer);
			return 1;
		}
	}
	return 0;
}

static inline int reclaim_buffer_early(struct buffer_head *buffer)
{
#ifdef BUFFER_PARANOIA_DEBUG
	if (debug_buffer >= 2)
		return reclaim_buffer(buffer);
#endif
	return 0;
}

static inline int is_reclaim_buffer_early(void)
{
#ifdef BUFFER_PARANOIA_DEBUG
	if (debug_buffer >= 2)
		return 1;
#endif
	return 0;
}

void set_buffer_state_list(struct buffer_head *buffer, unsigned state, struct list_head *list)
{
	list_move_tail(&buffer->link, list);
	buffer->state = state;
	/* state was changed, try to reclaim */
	reclaim_buffer_early(buffer);
}

static inline void set_buffer_state(struct buffer_head *buffer, unsigned state)
{
	set_buffer_state_list(buffer, state, buffers + state);
}

void tux3_set_buffer_dirty_list(struct buffer_head *buffer, int delta,
				struct list_head *head)
{
	set_buffer_state_list(buffer, BUFFER_DIRTY + delta_when(delta), head);
}

void tux3_set_buffer_dirty(struct buffer_head *buffer, int delta)
{
	struct list_head *head = dirty_head_when(&buffer->map->dirty, delta);
	tux3_set_buffer_dirty_list(buffer, delta, head);
}

struct buffer_head *set_buffer_dirty(struct buffer_head *buffer)
{
	tux3_set_buffer_dirty(buffer, DEFAULT_DIRTY_WHEN);
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

#ifdef BUFFER_PARANOIA_DEBUG
static void __free_buffer(struct buffer_head *buffer)
{
	list_del(&buffer->link);
	free(buffer->data);
	free(buffer);
}
#endif

static void free_buffer(struct buffer_head *buffer)
{
#ifdef BUFFER_PARANOIA_DEBUG
	if (debug_buffer) {
		__free_buffer(buffer);
		buffer_count--;
		return;
	}
#endif
	/* insert at head, not tail? */
	set_buffer_state(buffer, BUFFER_FREED);
	buffer->map = NULL;
	buffer_count--;
}

void blockput(struct buffer_head *buffer)
{
	assert(buffer);
	assert(buffer->count > 0);
	buftrace("Release buffer %Lx, count = %i, state = %i", buffer->index, buffer->count, buffer->state);
	buffer->count--;
	if (buffer->count == 0) {
		buftrace("Free buffer %Lx", buffer->index);
		assert(!buffer_dirty(buffer));
		assert(hlist_unhashed(&buffer->hashlink));
		assert(list_empty(&buffer->lru));
		free_buffer(buffer);
		return;
	}

	reclaim_buffer_early(buffer);
}

void get_bh(struct buffer_head *buffer)
{
	assert(buffer->count >= 1);
	buffer->count++;
}

void blockput_free(struct buffer_head *buffer)
{
	assert(buffer_dirty(buffer));

	if (bufcount(buffer) != 2) { /* caller + hashlink == 2 */
		warn("free block %Lx/%x still in use!",
		     bufindex(buffer), bufcount(buffer));
		blockput(buffer);
		assert(bufcount(buffer) == 1);
		return;
	}
	set_buffer_empty(buffer); // free it!!! (and need a buffer free state)
	blockput(buffer);
}

unsigned buffer_hash(block_t block)
{
	return (((block >> 32) ^ (block_t)block) * 978317583) % BUFFER_BUCKETS;
}

void insert_buffer_hash(struct buffer_head *buffer)
{
	map_t *map = buffer->map;
	struct hlist_head *bucket = map->hash + buffer_hash(buffer->index);
	get_bh(buffer); /* get additonal refcount for hashlink */
	hlist_add_head(&buffer->hashlink, bucket);
	list_add_tail(&buffer->lru, &lru_buffers);
}

void remove_buffer_hash(struct buffer_head *buffer)
{
	list_del_init(&buffer->lru);
	hlist_del_init(&buffer->hashlink);
	blockput(buffer); /* put additonal refcount for hashlink */
}

static void evict_buffer(struct buffer_head *buffer)
{
	buftrace("evict buffer [%Lx]", buffer->index);
	assert(buffer_clean(buffer) || buffer_empty(buffer));
	assert(buffer->count == 1);
	reclaim_buffer(buffer);
}

struct buffer_head *new_buffer(map_t *map)
{
	struct buffer_head *buffer = NULL;
	struct list_head *freed_list = &buffers[BUFFER_FREED];
	int err;

	if (!list_empty(freed_list)) {
		buffer = list_entry(freed_list->next, struct buffer_head, link);
		goto have_buffer;
	}

	if (buffer_count >= max_buffers) {
		buftrace("try to evict buffers");
		struct buffer_head *safe, *victim;
		int count = 0;
	
		list_for_each_entry_safe(victim, safe, &lru_buffers, lru) {
			if (reclaim_buffer(victim)) {
				if (++count == max_evict)
					break;
			}
		}

		if (!list_empty(freed_list)) {
			buffer = list_entry(freed_list->next, struct buffer_head, link);
			goto have_buffer;
		}
	}

	buftrace("expand buffer pool");
	if (buffer_count == max_buffers) {
		warn("Maximum buffer count exceeded (%i)", buffer_count);
		return ERR_PTR(-ENOMEM);
	}

	buffer = malloc(sizeof(struct buffer_head));
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	*buffer = (struct buffer_head){
		.state	= BUFFER_FREED,
		.link	= LIST_HEAD_INIT(buffer->link),
		.lru	= LIST_HEAD_INIT(buffer->lru),
	};
	INIT_HLIST_NODE(&buffer->hashlink);

	err = posix_memalign(&buffer->data, SECTOR_SIZE, 1 << map->dev->bits);
	if (err) {
		warn("Error: %s unable to expand buffer pool", strerror(err));
		free(buffer);
		return ERR_PTR(-err);
	}

have_buffer:
	assert(buffer->count == 0);
	assert(buffer->state == BUFFER_FREED);
	buffer->map = map;
	buffer->count = 1;
	set_buffer_empty(buffer);
	buffer_count++;
	return buffer;
}

struct buffer_head *peekblk(map_t *map, block_t block)
{
	struct hlist_head *bucket = map->hash + buffer_hash(block);
	struct buffer_head *buffer;
	struct hlist_node *node;
	hlist_for_each_entry(buffer, node, bucket, hashlink) {
		if (buffer->index == block) {
			get_bh(buffer);
			return buffer;
		}
	}
	return NULL;
}

struct buffer_head *blockget(map_t *map, block_t block)
{
	struct hlist_head *bucket = map->hash + buffer_hash(block);
	struct buffer_head *buffer;
	struct hlist_node *node;
	hlist_for_each_entry(buffer, node, bucket, hashlink) {
		if (buffer->index == block) {
			list_move_tail(&buffer->lru, &lru_buffers);
			get_bh(buffer);
			return buffer;
		}
	}

	buftrace("make buffer [%Lx]", block);
	buffer = new_buffer(map);
	if (IS_ERR(buffer))
		return NULL; // ERR_PTR me!!!
	buffer->index = block;
	insert_buffer_hash(buffer);
	return buffer;
}

struct buffer_head *blockread(map_t *map, block_t block)
{
	struct buffer_head *buffer = blockget(map, block);
	if (buffer && buffer_empty(buffer)) {
		struct iovec iov[1];
		struct buffer_head *bufv[1];
		struct bufvec bufvec = {
			.bufv = bufv,
			.iov = iov,
			.max_count = 1,
		};
		bufvec_add(&bufvec, buffer);
		buftrace("read buffer %Lx, state %i", buffer->index, buffer->state);
		int err = buffer->map->io(READ, &bufvec);
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
			if (!is_reclaim_buffer_early())
				reclaim_buffer(buffer);
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
			if (buffer->count == 1) {
				if (!buffer_empty(buffer))
					set_buffer_empty(buffer);
				if (!is_reclaim_buffer_early())
					evict_buffer(buffer);
			}
		}
	}
}

static int buffer_index_cmp(void *priv, struct list_head *a,
			    struct list_head *b)
{
	struct buffer_head *buf_a = list_entry(a, struct buffer_head, link);
	struct buffer_head *buf_b = list_entry(b, struct buffer_head, link);

	if (bufindex(buf_a) < bufindex(buf_b))
		return -1;
	else if (bufindex(buf_a) > bufindex(buf_b))
		return 1;
	return 0;
}

int flush_list(struct list_head *head)
{
	struct bufvec *bufvec;
	struct buffer_head *buffer, *n;
	int err = 0;

	if (list_empty(head))
		return 0;

	bufvec = bufvec_alloc(MAX_EXTENT);
	if (!bufvec)
		return -ENOMEM;

	list_sort(NULL, head, buffer_index_cmp);

	list_for_each_entry_safe(buffer, n, head, link) {
		assert(buffer_dirty(buffer));
		while (!bufvec_add(bufvec, buffer)) {
			err = bufvec_first_buf(bufvec)->map->io(WRITE, bufvec);
			if (err)
				goto error;
		}
	}
	while (bufvec_inuse(bufvec)) {
		err = bufvec_first_buf(bufvec)->map->io(WRITE, bufvec);
		if (err)
			goto error;
	}

error:
	bufvec_free(bufvec);

	return err;
}

int flush_buffers(map_t *map)
{
	return flush_list(dirty_head(&map->dirty));
}

int flush_state(unsigned state)
{
	return flush_list(buffers + state);
}

#ifdef BUFFER_PARANOIA_DEBUG
static void __destroy_buffers(void)
{
	struct buffer_head *buffer, *safe;
	struct list_head *head;

	/* If debug_buffer, buffer should already be freed */

	for (int i = 0; i < BUFFER_STATES; i++) {
		head = buffers + i;
		if (!debug_buffer) {
			list_for_each_entry_safe(buffer, safe, head, link) {
				list_del(&buffer->lru);
				__free_buffer(buffer);
			}
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

	/*
	 * If buffer is dirty, it may not be on buffers state list
	 * (e.g. buffer may be on map->dirty).
	 */
	if (!debug_buffer) {
		list_for_each_entry_safe(buffer, safe, &lru_buffers, lru) {
			assert(buffer_dirty(buffer));
			list_del(&buffer->lru);
			__free_buffer(buffer);
		}
	}
	if (!list_empty(&lru_buffers)) {
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
}

static void destroy_buffers(void)
{
	atexit(__destroy_buffers);
}
#else /* !BUFFER_PARANOIA_DEBUG */
static struct buffer_head *prealloc_heads;
static void *data_pool;

static int preallocate_buffers(unsigned bufsize)
{
	int i, err = -ENOMEM; /* if malloc fails */

	buftrace("Pre-allocating buffers...");
	prealloc_heads = malloc(max_buffers * sizeof(*prealloc_heads));
	if (!prealloc_heads)
		goto buffers_allocation_failure;
	buftrace("Pre-allocating data for buffers...");
	err = posix_memalign(&data_pool, SECTOR_SIZE, max_buffers * bufsize);
	if (err)
		goto data_allocation_failure;

	//memset(data_pool, 0xdd, max_buffers*bufsize); /* first time init to deadly data */
	for (i = 0; i < max_buffers; i++) {
		prealloc_heads[i] = (struct buffer_head){
			.data	= data_pool + i*bufsize,
			.state	= BUFFER_FREED,
			.lru	= LIST_HEAD_INIT(prealloc_heads[i].lru),
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
	return -err;
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

static int dev_blockio(int rw, struct bufvec *bufvec)
{
	block_t block = bufvec_first_index(bufvec);
	unsigned count = bufvec_inuse(bufvec);
	int err;

	assert(bufvec_first_buf(bufvec)->map->dev->bits >= 6 &&
	       bufvec_first_buf(bufvec)->map->dev->fd);

#ifdef BUFFER_FOR_TUX3
	err = blockio_vec(rw, bufvec, count, block);
#else
	err = iovabs(bufvec_first_buf(bufvec)->map->dev->fd, bufvec->iov,
		     count, rw, block << dev->bits);
#endif
	if (!err) {
		for (unsigned i = 0; i < count; i++)
			set_buffer_clean(bufvec_bufv(bufvec)[i]);
		bufvec_io_done(bufvec, count);
	}
	return err;
}

int dev_errio(int rw, struct bufvec *bufvec)
{
	assert(0);
	return -EIO;
}

void init_dirty_buffers(struct dirty_buffers *dirty)
{
	for (int i = 0; i < BUFFER_DIRTY_STATES; i ++)
		INIT_LIST_HEAD(&dirty->heads[i]);
}

map_t *new_map(struct dev *dev, blockio_t *io)
{
	map_t *map = malloc(sizeof(*map)); // error???
	*map = (map_t){
		.dev	= dev,
		.io	= io ? io : dev_blockio
	};
	init_dirty_buffers(&map->dirty);
	for (int i = 0; i < BUFFER_BUCKETS; i++)
		INIT_HLIST_HEAD(&map->hash[i]);
	return map;
}

void free_map(map_t *map)
{
	for (int i = 0; i < BUFFER_DIRTY_STATES; i ++)
		assert(list_empty(dirty_head_when(&map->dirty, i)));

	for (int i = 0; i < BUFFER_BUCKETS; i++) {
		struct hlist_head *bucket = &map->hash[i];
		struct buffer_head *buffer;
		struct hlist_node *node, *n;
		hlist_for_each_entry_safe(buffer, node, n, bucket, hashlink)
			evict_buffer(buffer);
	}
	free(map);
}

/*
 * Helper for waiting I/O (stub)
 */

void tux3_iowait_init(struct iowait *iowait)
{
}

void tux3_iowait_wait(struct iowait *iowait)
{
}

/*
 * Buffer I/O vector
 */

void bufvec_free(struct bufvec *bufvec)
{
	free(bufvec);
}

struct bufvec *bufvec_alloc(unsigned max_count)
{
	struct bufvec *bufvec;
	unsigned bufv_size = max_count * sizeof(struct buffer_head *);
	unsigned iovec_size = max_count * sizeof(struct iovec);

	bufvec = malloc(sizeof(*bufvec) + iovec_size + bufv_size);
	if (!bufvec)
		return ERR_PTR(-ENOMEM);

	memset(bufvec, 0, sizeof(*bufvec) + bufv_size + iovec_size);
	bufvec->bufv = (void *)bufvec + sizeof(*bufvec);
	bufvec->iov = (void *)bufvec->bufv + bufv_size;
	bufvec->max_count = max_count;

	return bufvec;
}

/*
 * Add buffer to bufvec. If there is no space or buffer is not
 * logically contiguous, return 0 and fail to add.
 */
int bufvec_add(struct bufvec *bufvec, struct buffer_head *buffer)
{
	/* Check if buffer is logically contiguous */
	if (bufvec_inuse(bufvec)) {
		block_t prev = bufvec_last_index(bufvec);
		if (prev != bufindex(buffer) - 1)
			return 0;
	}

	if (bufvec->count == bufvec->max_count) {
		if (bufvec->pos == 0)
			return 0;

		unsigned size;
		/* If there is space already done, use it */
		size = bufvec_inuse(bufvec) * sizeof(struct buffer_head *);
		memmove(bufvec->bufv, bufvec_bufv(bufvec), size);
		size = bufvec_inuse(bufvec) * sizeof(struct iovec);
		memmove(bufvec->iov, bufvec_iov(bufvec), size);

		bufvec->count -= bufvec->pos;
		bufvec->pos = 0;
	}

	bufvec->bufv[bufvec->count] = buffer;
	bufvec->iov[bufvec->count].iov_base = bufdata(buffer);
	bufvec->iov[bufvec->count].iov_len = bufsize(buffer);
	bufvec->count++;

	return 1;
}

void bufvec_io_done(struct bufvec *bufvec, unsigned done_count)
{
	assert(bufvec_inuse(bufvec) >= done_count);
	bufvec->pos += done_count;
}
