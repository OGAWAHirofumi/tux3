/*
 * Write back buffers
 */

#include <linux/list_sort.h>

/*
 * Helper for waiting I/O
 */

static void iowait_inflight_inc(struct iowait *iowait)
{
	atomic_inc(&iowait->inflight);
}

static void iowait_inflight_dec(struct iowait *iowait)
{
	if (atomic_dec_and_test(&iowait->inflight))
		complete(&iowait->done);
}

void tux3_iowait_init(struct iowait *iowait)
{
	/*
	 * Grab 1 to prevent the partial complete until all I/O is
	 * submitted
	 */
	init_completion(&iowait->done);
	atomic_set(&iowait->inflight, 1);
}

void tux3_iowait_wait(struct iowait *iowait)
{
	/* All I/O was submitted, release initial 1, then wait I/O */
	iowait_inflight_dec(iowait);
	wait_for_completion(&iowait->done);
}

/*
 * Helper for buffer vector I/O.
 */

#define buffers_entry(x) \
	list_entry(x, struct buffer_head, b_assoc_buffers)

/* Initialize bufvec */
static void bufvec_init(struct bufvec *bufvec, struct list_head *head)
{
	INIT_LIST_HEAD(&bufvec->contig);
	bufvec->buffers		= head;
	bufvec->contig_count	= 0;
	bufvec->on_page_idx	= 0;
	bufvec->bio		= NULL;
	bufvec->bio_lastbuf	= NULL;
}

static void bufvec_free(struct bufvec *bufvec)
{
	/* FIXME: on error path, this will happens */
	assert(!bufvec->buffers || list_empty(bufvec->buffers));
	assert(list_empty(&bufvec->contig));
	assert(bufvec->bio == NULL);
}

static inline void bufvec_buffer_move_to_contig(struct bufvec *bufvec,
						struct buffer_head *buffer)
{
	/*
	 * This is called by backend, it means buffer state should be
	 * stable. So, we don't need lock for buffer state list
	 * (->b_assoc_buffers).
	 *
	 * FIXME: above is true?
	 */
	list_move_tail(&buffer->b_assoc_buffers, &bufvec->contig);
	buffer->b_assoc_map = NULL;
	bufvec->contig_count++;
}

/*
 * Try to add buffer to bufvec as contiguous range.
 *
 * return value:
 * 1 - success
 * 0 - fail to add
 */
int bufvec_contig_add(struct bufvec *bufvec, struct buffer_head *buffer)
{
	/* Check if buffer is logically contiguous */
	if (bufvec_contig_count(bufvec)) {
		block_t last = bufvec_contig_last_index(bufvec);
		if (last != bufindex(buffer) - 1)
			return 0;
	}

	bufvec_buffer_move_to_contig(bufvec, buffer);

	return 1;
}

/*
 * Try to collect logically contiguous range from bufvec->buffers.
 */
static void bufvec_contig_collect(struct bufvec *bufvec)
{
	struct buffer_head *buffer;
	block_t last_index;

	/* If there is in-progress contiguous range, leave as is */
	if (bufvec_contig_count(bufvec))
		return;
	assert(!list_empty(bufvec->buffers));

	buffer = buffers_entry(bufvec->buffers->next);
	do {
		bufvec_buffer_move_to_contig(bufvec, buffer);
		trace("buffer %p", buffer);

		if (list_empty(bufvec->buffers))
			break;

		last_index = bufindex(buffer);
		buffer = buffers_entry(bufvec->buffers->next);
	} while (last_index == bufindex(buffer) - 1);
}

/*
 * Special purpose single pointer list (FIFO order) for buffers on bio
 */
static void bufvec_bio_add_buffer(struct bufvec *bufvec,
				  struct buffer_head *new)
{
	new->b_private = NULL;

	if (bufvec->bio_lastbuf)
		bufvec->bio_lastbuf->b_private = new;
	else
		bufvec->bio->bi_private = new;

	bufvec->bio_lastbuf = new;
}

static struct buffer_head *bufvec_bio_del_buffer(struct bio *bio)
{
	struct buffer_head *buffer = bio->bi_private;

	if (buffer) {
		bio->bi_private = buffer->b_private;
		buffer->b_private = NULL;
	}

	return buffer;
}

static struct sb *bufvec_bio_sb(struct bio *bio)
{
	struct buffer_head *buffer = bio->bi_private;
	assert(buffer);
	return tux_sb(buffer_inode(buffer)->i_sb);
}

static struct bio *bufvec_bio_alloc(struct sb *sb, unsigned int count,
				    block_t physical,
				    void (*end_io)(struct bio *, int))
{
	gfp_t gfp_flags = GFP_NOFS;
	struct bio *bio;

	count = min_t(unsigned int, count, bio_get_nr_vecs(vfs_sb(sb)->s_bdev));

	bio = bio_alloc(gfp_flags, count);
	/* This retry is from mpage_alloc() */
	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (count /= 2))
			bio = bio_alloc(gfp_flags, count);
	}
	assert(bio);	/* GFP_NOFS shouldn't fail to allocate */

	bio->bi_bdev	= vfs_sb(sb)->s_bdev;
	bio->bi_sector	= physical << (sb->blockbits - 9);
	bio->bi_end_io	= end_io;

	return bio;
}

static void bufvec_submit_bio(struct bufvec *bufvec)
{
	struct bio *bio = bufvec->bio;
	struct iowait *iowait = bufvec_bio_sb(bio)->iowait;

	bufvec->bio = NULL;
	bufvec->bio_lastbuf = NULL;

	trace("bio %p, physical %Lu, count %u", bio,
	      (block_t)bio->bi_sector >> (bufvec_bio_sb(bio)->blockbits - 9),
	      bio->bi_size >> bufvec_bio_sb(bio)->blockbits);

	iowait_inflight_inc(iowait);
	submit_bio(WRITE, bio);
}

/*
 * We flush all buffers on this page?
 *
 * The page may have the dirty buffer for both of "delta" and
 * "rollup", and we may flush only dirty buffers for "delta". So, if
 * the page still has the dirty buffer, we should still keep the page
 * dirty for "rollup".
 */
static int keep_page_dirty(struct bufvec *bufvec, struct page *page)
{
	struct buffer_head *first = page_buffers(page);
	struct inode *inode = buffer_inode(first);

	if (tux_inode(inode)->inum == TUX_VOLMAP_INO) {
		struct buffer_head *tmp = first;
		unsigned count = 0;
		do {
			if (buffer_dirty(tmp)) {
				count++;
				/* dirty buffers > flushing buffers? */
				if (count > bufvec->on_page_idx)
					return 1;
			}
			tmp = tmp->b_this_page;
		} while (tmp != first);
	}

	return 0;
}

/* Preparation and lock page for I/O */
static void
bufvec_prepare_and_lock_page(struct bufvec *bufvec, struct page *page)
{
	int ret;

	lock_page(page);
	assert(PageDirty(page));
	assert(!PageWriteback(page));

	/* Set it before clearing dirty, so dirty or writeback are presented */
	set_page_writeback(page);

	/*
	 * NOTE: This has the race if there is concurrent mark
	 * dirty. But we shouldn't use concurrent dirty [B] on volmap.
	 *
	 *           [ A ]                        [ B ]
	 * if (!keep_page_dirty())
	 *                                   mark_buffer_dirty()
	 *                                       TestSetPageDirty()
	 *     // this lost dirty of [B]
	 *     clear_dirty_for_io()
	 */
	if (!keep_page_dirty(bufvec, page)) {
		ret = clear_page_dirty_for_io(page);
		assert(ret);
	}
}

static void bufvec_prepare_and_unlock_page(struct page *page)
{
	unlock_page(page);
}

/* Completion of page for I/O */
static void bufvec_page_end_io(struct page *page, int uptodate, int quiet)
{
	end_page_writeback(page);
}

/* Preparation buffer for I/O */
static void bufvec_prepare_buffer(struct buffer_head *buffer)
{
	tux3_clear_bufdelta(buffer);	/* FIXME: hack for save delta */
	assert(buffer_dirty(buffer));	/* Who cleared the dirty? */
	clear_buffer_dirty(buffer);
}

/* Completion of buffer for I/O */
static void bufvec_buffer_end_io(struct buffer_head *buffer, int uptodate,
				 int quiet)
{
	char b[BDEVNAME_SIZE];

	if (uptodate)
		set_buffer_uptodate(buffer);
	else {
		if (!quiet) {
			printk(KERN_WARNING "lost page write due to "
			       "I/O error on %s\n",
			       bdevname(buffer->b_bdev, b));
		}
		set_buffer_write_io_error(buffer);
		clear_buffer_uptodate(buffer);
	}
}

/* Check whether buffers are contiguous or not. */
static int bufvec_is_multiple_ranges(struct bufvec *bufvec)
{
	block_t logical, physical;
	unsigned int i;

	logical = bufindex(bufvec->on_page[0].buffer);
	physical = bufvec->on_page[0].block;
	for (i = 1; i < bufvec->on_page_idx; i++) {
		if (logical + i != bufindex(bufvec->on_page[i].buffer) ||
		    physical + i != bufvec->on_page[i].block) {
			return 1;
		}
	}

	return 0;
}

/*
 * BIO completion for complex case. There are multiple ranges on the
 * page, and those are submitted BIO for each range. So, completion of
 * the page is only if all BIOs are done.
 */
static void bufvec_end_io_multiple(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	const int quiet = test_bit(BIO_QUIET, &bio->bi_flags);
	struct sb *sb;
	struct page *page;
	struct buffer_head *buffer, *first, *tmp;
	unsigned long flags;

	trace("bio %p, err %d", bio, err);

	/* FIXME: inode is still guaranteed to be available? */
	sb = bufvec_bio_sb(bio);
	buffer = bufvec_bio_del_buffer(bio);
	page = buffer->b_page;
	first = page_buffers(page);

	trace("buffer %p", buffer);
	bufvec_buffer_end_io(buffer, uptodate, quiet);
	put_bh(buffer);

	iowait_inflight_dec(sb->iowait);
	bio_put(bio);

	/* Check buffers on the page. If all was done, clear writeback */
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);

	clear_buffer_async_write(buffer);
	tmp = buffer->b_this_page;
	while (tmp != buffer) {
		if (buffer_async_write(tmp))
			goto still_busy;
		tmp = tmp->b_this_page;
	}
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);

	bufvec_page_end_io(page, uptodate, quiet);
	return;

still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
}

/*
 * This page across on multiple ranges.
 *
 * To handle I/O completion properly, this sets "buffer_async_write"
 * to all buffers, then submits buffers with own bio. And on end_io,
 * we check if "buffer_async_write" of all buffers was cleared.
 *
 * FIXME: Some buffers on the page can be contiguous, we can submit
 * those as one bio if contiguous.
 */
static void bufvec_bio_add_multiple(struct bufvec *bufvec)
{
	/* FIXME: inode is still guaranteed to be available? */
	struct sb *sb = tux_sb(buffer_inode(bufvec->on_page[0].buffer)->i_sb);
	struct page *page;
	unsigned int i;

	/* If there is bio, submit it */
	if (bufvec->bio)
		bufvec_submit_bio(bufvec);

	page = bufvec->on_page[0].buffer->b_page;

	/* Prepare the page and buffers on the page for I/O */
	bufvec_prepare_and_lock_page(bufvec, page);
	/* Set buffer_async_write to all buffers at first, then submit */
	for (i = 0; i < bufvec->on_page_idx; i++) {
		struct buffer_head *buffer = bufvec->on_page[i].buffer;
		bufvec_prepare_buffer(buffer);
		/* Buffer locking order for I/O is lower index to
		 * bigger index. And grouped by inode. FIXME: is this sane? */
		/* lock_buffer(buffer); FIXME: need? */
		set_buffer_async_write(buffer);
	}

	for (i = 0; i < bufvec->on_page_idx; i++) {
		struct buffer_head *buffer = bufvec->on_page[i].buffer;
		block_t physical = bufvec->on_page[i].block;
		unsigned int length = bufsize(buffer);
		unsigned int offset = bh_offset(buffer);

		bufvec->bio = bufvec_bio_alloc(sb, 1, physical,
					       bufvec_end_io_multiple);

		trace("page %p, index %Lu, physical %Lu, length %u, offset %u",
		      page, bufindex(bufvec->on_page[i].buffer), physical,
		      length, offset);
		if (!bio_add_page(bufvec->bio, page, length, offset))
			assert(0);	/* why? */

		get_bh(buffer);
		bufvec_bio_add_buffer(bufvec, buffer);

		bufvec_submit_bio(bufvec);
	}
	bufvec_prepare_and_unlock_page(page);

	bufvec->on_page_idx = 0;
}

/*
 * bio completion for bufvec based I/O
 */
static void bufvec_end_io(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	const int quiet = test_bit(BIO_QUIET, &bio->bi_flags);
	struct sb *sb;
	struct page *page, *last_page;

	trace("bio %p, err %d", bio, err);

	/* FIXME: inode is still guaranteed to be available? */
	sb = bufvec_bio_sb(bio);

	/* Remove buffer from bio, then unlock buffer */
	last_page = NULL;
	while (1) {
		struct buffer_head *buffer = bufvec_bio_del_buffer(bio);
		if (!buffer)
			break;

		page = buffer->b_page;

		trace("buffer %p", buffer);
		put_bh(buffer);

		if (page != last_page) {
			bufvec_page_end_io(page, uptodate, quiet);
			last_page = page;
		}
	}

	iowait_inflight_dec(sb->iowait);
	bio_put(bio);
}

/*
 * Try to add buffers on a page to bio. If it was failed, we submit
 * bio, then add buffers on new bio.
 *
 * FIXME: We can free buffers early, and avoid to use buffers in I/O
 * completion, after prepared the page (like __mpage_writepage).
 */
static void bufvec_bio_add_page(struct bufvec *bufvec)
{
	/* FIXME: inode is still guaranteed to be available? */
	struct inode *inode = buffer_inode(bufvec->on_page[0].buffer);
	struct sb *sb = tux_sb(inode->i_sb);
	struct page *page;
	block_t physical;
	unsigned int i, length, offset;

	page = bufvec->on_page[0].buffer->b_page;
	physical = bufvec->on_page[0].block;
	offset = bh_offset(bufvec->on_page[0].buffer);
	length = bufvec->on_page_idx << sb->blockbits;

	trace("page %p, index %Lu, physical %Lu, length %u, offset %u",
	      page, bufindex(bufvec->on_page[0].buffer), physical,
	      length, offset);

	/* Try to add buffers to exists bio */
	if (!bufvec->bio || !bio_add_page(bufvec->bio, page, length, offset)) {
		/* Couldn't add. So submit old bio and allocate new bio */
		if (bufvec->bio)
			bufvec_submit_bio(bufvec);

		bufvec->bio =
			bufvec_bio_alloc(sb, bufvec_contig_count(bufvec) + 1,
					 physical, bufvec_end_io);

		if (!bio_add_page(bufvec->bio, page, length, offset))
			assert(0);	/* why? */
	}

	/* Prepare the page, and buffers on the page for I/O */
	bufvec_prepare_and_lock_page(bufvec, page);
	for (i = 0; i < bufvec->on_page_idx; i++) {
		struct buffer_head *buffer = bufvec->on_page[i].buffer;
		bufvec_prepare_buffer(buffer);
		get_bh(buffer);
		bufvec_bio_add_buffer(bufvec, buffer);
	}
	bufvec_prepare_and_unlock_page(page);

	bufvec->on_page_idx = 0;
}

/* Check whether "physical" is contiguous with bio */
static int bufvec_bio_is_contiguous(struct bufvec *bufvec, block_t physical)
{
	struct bio *bio = bufvec->bio;
	struct sb *sb = bufvec_bio_sb(bio);
	block_t next;

	next = (block_t)bio->bi_sector + (bio->bi_size >> 9);
	return next == (physical << (sb->blockbits - 9));
}

/* Get the page of next candidate buffer. */
static struct page *bufvec_next_buffer_page(struct bufvec *bufvec)
{
	if (!list_empty(&bufvec->contig))
		return bufvec_contig_buf(bufvec)->b_page;

	if (bufvec->buffers && !list_empty(bufvec->buffers))
		return buffers_entry(bufvec->buffers->next)->b_page;

	return NULL;
}

/*
 * Prepare and submit I/O for specified range.
 *
 * This submits the contiguous range at once as much as possible.
 *
 * But if the page across on multiple ranges, we can't know when all
 * I/O was done on the page (and when we can clear the writeback flag).
 * So, we use different strategy. Those ranges are submitted as
 * multiple BIOs, and use BH_Update_Lock for exclusive check if I/O was
 * done.
 *
 * This doesn't guarantee all candidate buffers are submitted. E.g. if
 * the page across on multiple ranges, the page will be pending until
 * all physical addresses was specified.
 *
 * return value:
 * < 0 - error
 *   0 - success
 */
int bufvec_io(int rw, struct bufvec *bufvec, block_t physical, unsigned count)
{
	unsigned int i;
	int need_check = 0;

	trace("index %Lu, contig_count %u, physical %Lu, count %u",
	      bufvec_contig_index(bufvec), bufvec_contig_count(bufvec),
	      physical, count);

	assert(rw == WRITE);	/* FIXME: now only support WRITE */
	assert(bufvec_contig_count(bufvec) >= count);

	if (bufvec->on_page_idx) {
		/*
		 * If there is the pending buffers on the page, and buffers
		 * was not contiguous, this is the complex case.
		 */
		need_check = 1;
	} else if (bufvec->bio && !bufvec_bio_is_contiguous(bufvec, physical)) {
		/*
		 * If new range is not contiguous with the pending bio,
		 * submit the pending bio.
		 */
		bufvec_submit_bio(bufvec);
	}

	/* Add buffers to bio for each page */
	for (i = 0; i < count; i++) {
		struct buffer_head *buffer = bufvec_contig_buf(bufvec);

		/* FIXME: need lock? (buffer is already owned by backend...) */
		bufvec->contig_count--;
		list_del_init(&buffer->b_assoc_buffers);

		/* Collect buffers on the same page */
		bufvec->on_page[bufvec->on_page_idx].buffer = buffer;
		bufvec->on_page[bufvec->on_page_idx].block = physical + i;
		bufvec->on_page_idx++;

		/* If next buffer isn't on same page, add buffers to bio */
		if (buffer->b_page != bufvec_next_buffer_page(bufvec)) {
			int multiple = 0;
			if (need_check) {
				need_check = 0;
				multiple = bufvec_is_multiple_ranges(bufvec);
			}

			if (multiple)
				bufvec_bio_add_multiple(bufvec);
			else
				bufvec_bio_add_page(bufvec);
		}
	}

	/* If no more buffer, submit the pending bio */
	if (bufvec->bio && !bufvec_next_buffer_page(bufvec))
		bufvec_submit_bio(bufvec);

	return 0;
}

static int buffer_index_cmp(void *priv, struct list_head *a,
			    struct list_head *b)
{
	struct buffer_head *buf_a, *buf_b;

	buf_a = list_entry(a, struct buffer_head, b_assoc_buffers);
	buf_b = list_entry(b, struct buffer_head, b_assoc_buffers);

	if (bufindex(buf_a) < bufindex(buf_b))
		return -1;
	else if (bufindex(buf_a) > bufindex(buf_b))
		return 1;
	return 0;
}

/*
 * Flush buffers in head
 */
int flush_list(struct list_head *head)
{
	struct inode *inode;
	struct bufvec bufvec;
	struct buffer_head *buffer;
	int err = 0;

	/* FIXME: on error path, we have to do something for buffer state */

	if (list_empty(head))
		return 0;

	bufvec_init(&bufvec, head);

	/* Sort by bufindex() */
	list_sort(NULL, head, buffer_index_cmp);

	/* Use first buffer to get inode, all should be for this inode. */
	buffer = buffers_entry(head->next);
	inode = buffer_inode(buffer);

	while (bufvec_next_buffer_page(&bufvec)) {
		/* Collect contiguous buffer range */
		bufvec_contig_collect(&bufvec);

		/* Start I/O */
		err = tux_inode(inode)->io(WRITE, &bufvec);
		if (err)
			break;
	}

	bufvec_free(&bufvec);

	return err;
}

/*
 * I/O helper for physical index buffers (e.g. buffers on volmap)
 */
int tux3_volmap_io(int rw, struct bufvec *bufvec)
{
	block_t physical = bufvec_contig_index(bufvec);
	unsigned count = bufvec_contig_count(bufvec);

	/* FIXME: For now, this is only for write */
	assert(rw == WRITE);

	return blockio_vec(rw, bufvec, physical, count);
}
