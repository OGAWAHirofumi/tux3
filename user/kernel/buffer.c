/*
 * Buffer management
 */

#include "tux3.h"
#include "tux3_fork.h"

#ifndef trace
#define trace trace_on
#endif

/*
 * FIXME: Setting delta is not atomic with dirty for this buffer_head,
 */
#define BUFDELTA_AVAIL		1
#define BUFDELTA_BITS		order_base_2(BUFDELTA_AVAIL + TUX3_MAX_DELTA)
TUX3_DEFINE_STATE_FNS(unsigned long, buf, BUFDELTA_AVAIL, BUFDELTA_BITS,
		      BH_PrivateStart);

/*
 * FIXME: we should rewrite with own buffer management
 */

/*
 * FIXME: this is hack to save delta to linux buffer_head.
 * Inefficient, and this is not atomic with dirty bit change. And this
 * may not work on all arch (If set_bit() and cmpxchg() is not
 * exclusive, this has race).
 */
static void tux3_set_bufdelta(struct buffer_head *buffer, int delta)
{
	unsigned long state, old_state;

	delta = tux3_delta(delta);

	state = buffer->b_state;
	for (;;) {
		old_state = state;
		state = tux3_bufsta_update(old_state, delta);
		state = cmpxchg(&buffer->b_state, old_state, state);
		if (state == old_state)
			break;
	}
}

static void tux3_clear_bufdelta(struct buffer_head *buffer)
{
	unsigned long state, old_state;

	state = buffer->b_state;
	for (;;) {
		old_state = state;
		state = tux3_bufsta_clear(old_state);
		state = cmpxchg(&buffer->b_state, old_state, state);
		if (state == old_state)
			break;
	}
}

/*
 * Check buffer dirty and delta number atomically.
 * >= 0 - delta number of buffer
 *  < 0 - buffer is not dirty
 */
static int buffer_check_dirty_delta(unsigned long state)
{
	if (tux3_bufsta_has_delta(state))
		return tux3_bufsta_get_delta(state);
	/* Buffer is not dirty */
	return -1;	/* never much with tux3_delta() */
}

/* Check whether buffer was already dirtied atomically for delta */
int buffer_already_dirty(struct buffer_head *buffer, unsigned delta)
{
	unsigned long state = buffer->b_state;
	/* If buffer had same delta, buffer was already dirtied for delta */
	return buffer_check_dirty_delta(state) == tux3_delta(delta);
}

/* Check whether we can modify buffer atomically for delta */
int buffer_can_modify(struct buffer_head *buffer, unsigned delta)
{
	unsigned long state = buffer->b_state;
	/* If buffer is clean or dirtied for same delta, we can modify */
	return !tux3_bufsta_has_delta(state) ||
		tux3_bufsta_get_delta(state) == tux3_delta(delta);
}

/* Set our delta dirty bits, then add to our dirty buffers list */
static inline void __tux3_set_buffer_dirty_list(struct address_space *mapping,
			     struct buffer_head *buffer, int delta,
			     struct list_head *head)
{
	if (!buffer->b_assoc_map) {
		spin_lock(&mapping->private_lock);
		BUG_ON(!list_empty(&buffer->b_assoc_buffers));
		list_move_tail(&buffer->b_assoc_buffers, head);
		buffer->b_assoc_map = mapping;
		/* FIXME: hack for save delta */
		tux3_set_bufdelta(buffer, delta);
		spin_unlock(&mapping->private_lock);
	}
}

/*
 * Caller must hold lock_page() or backend (otherwise, you may race
 * with buffer fork or clear dirty)
 */
int tux3_set_buffer_dirty_list(struct address_space *mapping,
			       struct buffer_head *buffer, int delta,
			       struct list_head *head)
{
	/* FIXME: we better to set this by caller? */
	if (!buffer_uptodate(buffer))
		set_buffer_uptodate(buffer);

	/*
	 * Basically, open code of mark_buffer_dirty() without mark
	 * inode dirty.  Caller decides whether dirty inode or not.
	 */
	if (!test_set_buffer_dirty(buffer)) {
		struct page *page = buffer->b_page;

		/* Mark dirty for delta, then add buffer to our dirty list */
		__tux3_set_buffer_dirty_list(mapping, buffer, delta, head);

		if (!TestSetPageDirty(page)) {
			struct address_space *mapping = page->mapping;
			if (mapping)
				__tux3_set_page_dirty_account(page, mapping, 0);
			return 1;
		}
	}
	return 0;
}

int tux3_set_buffer_dirty(struct address_space *mapping,
			  struct buffer_head *buffer, int delta)
{
	struct list_head *head = tux3_dirty_buffers(mapping->host, delta);
	return tux3_set_buffer_dirty_list(mapping, buffer, delta, head);
}

/*
 * Caller must hold lock_page() or backend (otherwise, you may race
 * with buffer fork or set dirty)
 */
void tux3_clear_buffer_dirty(struct buffer_head *buffer, unsigned delta)
{
	struct address_space *buffer_mapping = buffer->b_assoc_map;

	/* The buffer must not need to fork */
	assert(buffer_can_modify(buffer, delta));

	if (buffer_mapping) {
		spin_lock(&buffer_mapping->private_lock);
		list_del_init(&buffer->b_assoc_buffers);
		buffer->b_assoc_map = NULL;
		tux3_clear_bufdelta(buffer);
		spin_unlock(&buffer_mapping->private_lock);

		clear_buffer_dirty(buffer);
	} else
		BUG_ON(!list_empty(&buffer->b_assoc_buffers));
}

/* Clear buffer dirty for I/O (Caller must remove buffer from list) */
static void tux3_clear_buffer_dirty_for_io(struct buffer_head *buffer,
					   struct sb *sb, block_t block)
{
	assert(list_empty(&buffer->b_assoc_buffers));
	assert(buffer_dirty(buffer));	/* Who cleared the dirty? */
	/* If buffer was hole and dirtied, it can be !buffer_mapped() */
	/*assert(buffer_mapped(buffer));*/
	assert(buffer_uptodate(buffer));

	/* Set up buffer for I/O. FIXME: need? */
	map_bh(buffer, vfs_sb(sb), block);
	clear_buffer_delay(buffer);

	/*buffer->b_assoc_map = NULL;*/	/* FIXME: hack for *_for_io_hack */
	tux3_clear_bufdelta(buffer);	/* FIXME: hack for save delta */
	clear_buffer_dirty(buffer);
}

/*
 * This is hack to know ->mapping in end_io.
 * So, tux3_clear_buffer_dirty_for_io() doesn't clear buffer->b_assoc_map.
 * FIXME: remove this hack.
 */
static void tux3_clear_buffer_dirty_for_io_hack(struct buffer_head *buffer)
{
	buffer->b_assoc_map = NULL;
}

/* This is called for the freeing block on volmap */
static void __blockput_free(struct sb *sb, struct buffer_head *buffer,
			    unsigned delta)
{
	/* FIXME: buffer was freed, so we would like to free cache */
	tux3_clear_buffer_dirty(buffer, delta);
	tux3_try_cancel_dirty_page(buffer->b_page);
	blockput(buffer);
}

void blockput_free(struct sb *sb, struct buffer_head *buffer)
{
	__blockput_free(sb, buffer, TUX3_INIT_DELTA);
}

void blockput_free_unify(struct sb *sb, struct buffer_head *buffer)
{
	__blockput_free(sb, buffer, sb->unify);
}

/* Copied from fs/buffer.c */
static void discard_buffer(struct buffer_head *buffer)
{
	/* FIXME: we need lock_buffer()? */
	lock_buffer(buffer);
	/*clear_buffer_dirty(buffer);*/
	buffer->b_bdev = NULL;
	clear_buffer_mapped(buffer);
	clear_buffer_req(buffer);
	clear_buffer_new(buffer);
	clear_buffer_delay(buffer);
	clear_buffer_unwritten(buffer);
	unlock_buffer(buffer);
}

/*
 * Invalidate buffer, this must be called from frontend like truncate.
 * Caller must hold lock_page(), and page->mapping must be valid.
 */
void tux3_invalidate_buffer(struct buffer_head *buffer)
{
	unsigned delta = tux3_inode_delta(buffer_inode(buffer));
	tux3_clear_buffer_dirty(buffer, delta);
	discard_buffer(buffer);
}

#include "buffer_writeback.c"
#include "buffer_fork.c"
