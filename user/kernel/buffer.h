#ifndef TUX3_BUFFER_H
#define TUX3_BUFFER_H

#ifdef __KERNEL__
#define BUFFER_DIRTY_STATES	4
#define DEFAULT_DIRTY_WHEN	0

enum {
	BUFFER_FREED, BUFFER_EMPTY, BUFFER_CLEAN, BUFFER_DIRTY,
	BUFFER_STATES = BUFFER_DIRTY + BUFFER_DIRTY_STATES
};

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
int flush_list(struct list_head *head);
#endif /* !__KERNEL__ */
#endif /* !TUX3_BUFFER_H */
