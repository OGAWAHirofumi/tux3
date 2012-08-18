#ifndef TUX3_BUFFER_H
#define TUX3_BUFFER_H

#ifdef __KERNEL__
#include "link.h"

/*
 * Choose carefully:
 * loff_t can be "long" or "long long" in userland. (not printf friendly)
 * sector_t can be "unsigned long" or "u64". (not printf friendly, and
 * would be hard to control on 32bits arch)
 *
 * we want 48bits for tux3, and error friendly. (FIXME: what is best?)
 */
typedef signed long long	block_t;

#define BUFFER_DIRTY_STATES	4
#define DEFAULT_DIRTY_WHEN	0

enum {
	BUFFER_FREED, BUFFER_EMPTY, BUFFER_CLEAN, BUFFER_DIRTY,
	BUFFER_STATES = BUFFER_DIRTY + BUFFER_DIRTY_STATES
};

static inline block_t bufindex(struct buffer_head *buffer);

static inline void *bufdata(struct buffer_head *buffer)
{
	return buffer->b_data;
}

static inline size_t bufsize(struct buffer_head *buffer)
{
	return buffer->b_size;
}

static inline int bufcount(struct buffer_head *buffer)
{
	return atomic_read(&buffer->b_count);
}

static inline int buffer_clean(struct buffer_head *buffer)
{
	return !buffer_dirty(buffer) || buffer_uptodate(buffer);
}

static inline void blockput(struct buffer_head *buffer)
{
	put_bh(buffer);
}

static inline void blockput_free(struct buffer_head *buffer)
{
	/* Untested */
	WARN_ON(1);
	bforget(buffer);
	blockput(buffer);
}

static inline int buffer_empty(struct buffer_head *buffer)
{
	return 1;
}

static inline struct buffer_head *set_buffer_empty(struct buffer_head *buffer)
{
	return buffer;
}

/* List of per-delta dirty buffers */
struct dirty_buffers {
	struct list_head heads[BUFFER_DIRTY_STATES];
};

/* Get offset of delta */
static inline unsigned delta_when(unsigned delta)
{
	return delta & (BUFFER_DIRTY_STATES - 1);
}

/* Get list of buffers when dirtied at delta */
static inline struct list_head *
dirty_head_when(struct dirty_buffers *dirty, unsigned delta)
{
	return &dirty->heads[delta_when(delta)];
}

static inline struct list_head *dirty_head(struct dirty_buffers *dirty)
{
	return dirty_head_when(dirty, DEFAULT_DIRTY_WHEN);
}

/* Can we modify buffer from delta */
static inline int buffer_can_modify(struct buffer_head *buffer, unsigned delta)
{
	return buffer_dirty(buffer);
}

void tux3_set_buffer_dirty_list(struct buffer_head *buffer, int delta,
				struct list_head *head);
void tux3_set_buffer_dirty(struct buffer_head *buffer, int delta);
void init_dirty_buffers(struct dirty_buffers *dirty);

/* buffer_writeback.c */
/* Helper for buffer vector I/O */
struct bufvec {
	struct list_head buffers;	/* The buffers added to the bio */
	unsigned count;			/* in-use count */
	struct bio *bio;
};

static inline unsigned bufvec_count(struct bufvec *bufvec)
{
	return bufvec->count;
}

static inline struct buffer_head *bufvec_first_buf(struct bufvec *bufvec)
{
	struct list_head *first = bufvec->buffers.next;
	assert(!list_empty(&bufvec->buffers));
	return list_entry(first, struct buffer_head, b_assoc_buffers);
}

static inline struct buffer_head *bufvec_last_buf(struct bufvec *bufvec)
{
	struct list_head *last = bufvec->buffers.prev;
	assert(!list_empty(&bufvec->buffers));
	return list_entry(last, struct buffer_head, b_assoc_buffers);
}

static inline block_t bufvec_first_index(struct bufvec *bufvec)
{
	return bufindex(bufvec_first_buf(bufvec));
}

static inline block_t bufvec_last_index(struct bufvec *bufvec)
{
	return bufindex(bufvec_last_buf(bufvec));
}

int bufvec_prepare_io(struct bufvec *bufvec, block_t physical, unsigned count);
int flush_list(struct list_head *head);
#endif /* !__KERNEL__ */
#endif /* !TUX3_BUFFER_H */
