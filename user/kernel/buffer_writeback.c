/*
 * Write back buffers
 */

#include "buffer_writebacklib.c"

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

static inline struct buffer_head *buffers_entry(struct list_head *x)
{
	return list_entry(x, struct buffer_head, b_assoc_buffers);
}

#define MAX_BUFVEC_COUNT	UINT_MAX

/* Initialize bufvec */
static void bufvec_init(struct bufvec *bufvec, struct address_space *mapping,
			struct list_head *head, struct tux3_iattr_data *idata)
{
	INIT_LIST_HEAD(&bufvec->contig);
	bufvec->buffers		= head;
	bufvec->contig_count	= 0;
	bufvec->idata		= idata;
	bufvec->mapping		= mapping;
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
	bufvec->contig_count++;
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

static struct address_space *bufvec_bio_mapping(struct bio *bio)
{
	struct buffer_head *buffer = bio->bi_private;
	assert(buffer);
	/* FIXME: we want to remove usage of b_assoc_map */
	return buffer->b_assoc_map;
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

static void bufvec_submit_bio(int rw, struct bufvec *bufvec)
{
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
	struct bio *bio = bufvec->bio;

	bufvec->bio = NULL;
	bufvec->bio_lastbuf = NULL;

	trace("bio %p, physical %Lu, count %u", bio,
	      (block_t)bio->bi_sector >> (sb->blockbits - 9),
	      bio->bi_size >> sb->blockbits);

	iowait_inflight_inc(sb->iowait);
	submit_bio(rw, bio);
}

/*
 * We flush all buffers on this page?
 *
 * The page may have the dirty buffer for both of "delta" and
 * "unify", and we may flush only dirty buffers for "delta". So, if
 * the page still has the dirty buffer, we should still keep the page
 * dirty for "unify".
 */
static int keep_page_dirty(struct bufvec *bufvec, struct page *page)
{
	struct buffer_head *first = page_buffers(page);
	struct inode *inode = bufvec_inode(bufvec);

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
	struct tux3_iattr_data *idata = bufvec->idata;
	pgoff_t last_index;
	unsigned offset;
	int old_flag, old_writeback;

	lock_page(page);
	assert(PageDirty(page));
	assert(!PageWriteback(page));

	/*
	 * Set "writeback" flag before clearing "dirty" flag, so, page
	 * presents either of "dirty" or "writeback" flag.  With this,
	 * free_forked_buffers() can check page flags without locking
	 * page. See FIXME of forked_buffers().
	 *
	 * And writeback flag prevents vmscan releases page.
	 */
	old_writeback = TestSetPageWriteback(page);
	assert(!old_writeback);

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
		old_flag = tux3_clear_page_dirty_for_io(page);
		assert(old_flag);
	}

	/*
	 * This fixes incoherency of page accounting and radix-tree
	 * tag by above change of dirty and writeback.
	 *
	 * NOTE: This is assuming to be called after clearing dirty
	 * (See comment of tux3_clear_page_dirty_for_io()).
	 */
	__tux3_test_set_page_writeback(page, old_writeback);

	/*
	 * Zero fill the page for mmap outside i_size after clear dirty.
	 *
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	offset = idata->i_size & (PAGE_CACHE_SIZE - 1);
	last_index = idata->i_size >> PAGE_CACHE_SHIFT;
	if (offset && last_index == page->index)
		zero_user_segment(page, offset, PAGE_CACHE_SIZE);
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
	struct address_space *mapping;
	struct page *page;
	struct buffer_head *buffer, *first, *tmp;
	unsigned long flags;

	trace("bio %p, err %d", bio, err);

	/* FIXME: inode is still guaranteed to be available? */
	mapping = bufvec_bio_mapping(bio);

	buffer = bufvec_bio_del_buffer(bio);
	page = buffer->b_page;
	first = page_buffers(page);

	trace("buffer %p", buffer);
	tux3_clear_buffer_dirty_for_io_hack(buffer);
	bufvec_buffer_end_io(buffer, uptodate, quiet);
	put_bh(buffer);

	iowait_inflight_dec(tux_sb(mapping->host->i_sb)->iowait);
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
static void bufvec_bio_add_multiple(int rw, struct bufvec *bufvec)
{
	/* FIXME: inode is still guaranteed to be available? */
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
	struct page *page;
	unsigned int i;

	/* If there is bio, submit it */
	if (bufvec->bio)
		bufvec_submit_bio(rw, bufvec);

	page = bufvec->on_page[0].buffer->b_page;

	/* Prepare the page and buffers on the page for I/O */
	bufvec_prepare_and_lock_page(bufvec, page);
	/* Set buffer_async_write to all buffers at first, then submit */
	for (i = 0; i < bufvec->on_page_idx; i++) {
		struct buffer_head *buffer = bufvec->on_page[i].buffer;
		block_t physical = bufvec->on_page[i].block;
		get_bh(buffer);
		tux3_clear_buffer_dirty_for_io(buffer, sb, physical);
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

		bufvec_bio_add_buffer(bufvec, buffer);

		bufvec_submit_bio(rw, bufvec);
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
	struct address_space *mapping;
	struct page *page, *last_page;

	trace("bio %p, err %d", bio, err);

	/* FIXME: inode is still guaranteed to be available? */
	mapping = bufvec_bio_mapping(bio);

	/* Remove buffer from bio, then unlock buffer */
	last_page = NULL;
	while (1) {
		struct buffer_head *buffer = bufvec_bio_del_buffer(bio);
		if (!buffer)
			break;

		page = buffer->b_page;

		trace("buffer %p", buffer);
		tux3_clear_buffer_dirty_for_io_hack(buffer);
		put_bh(buffer);

		if (page != last_page) {
			bufvec_page_end_io(page, uptodate, quiet);
			last_page = page;
		}
	}

	iowait_inflight_dec(tux_sb(mapping->host->i_sb)->iowait);
	bio_put(bio);
}

/*
 * Try to add buffers on a page to bio. If it was failed, we submit
 * bio, then add buffers on new bio.
 *
 * FIXME: We can free buffers early, and avoid to use buffers in I/O
 * completion, after prepared the page (like __mpage_writepage).
 */
static void bufvec_bio_add_page(int rw, struct bufvec *bufvec)
{
	/* FIXME: inode is still guaranteed to be available? */
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
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
			bufvec_submit_bio(rw, bufvec);

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
		block_t physical = bufvec->on_page[i].block;
		get_bh(buffer);
		tux3_clear_buffer_dirty_for_io(buffer, sb, physical);
		bufvec_bio_add_buffer(bufvec, buffer);
	}
	bufvec_prepare_and_unlock_page(page);

	bufvec->on_page_idx = 0;
}

/* Check whether "physical" is contiguous with bio */
static int bufvec_bio_is_contiguous(struct bufvec *bufvec, block_t physical)
{
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
	struct bio *bio = bufvec->bio;
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

	assert(rw & WRITE);	/* FIXME: now only support WRITE */
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
		bufvec_submit_bio(rw, bufvec);
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
				bufvec_bio_add_multiple(rw, bufvec);
			else
				bufvec_bio_add_page(rw, bufvec);
		}
	}

	/* If no more buffer, submit the pending bio */
	if (bufvec->bio && !bufvec_next_buffer_page(bufvec))
		bufvec_submit_bio(rw, bufvec);

	return 0;
}

static void bufvec_cancel_and_unlock_page(struct page *page,
					  const pgoff_t outside_index)
{
	/*
	 * If page is fully outside i_size, cancel dirty.
	 *
	 * If page is partially outside i_size, we have to check
	 * buffers. If all buffers aren't dirty, cancel dirty.
	 */
	if (page->index < outside_index)
		tux3_try_cancel_dirty_page(page);
	else
		cancel_dirty_page(page, PAGE_CACHE_SIZE);

	unlock_page(page);
}

/* Cancel dirty buffers fully outside i_size */
static void bufvec_cancel_dirty_outside(struct bufvec *bufvec)
{
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
	struct tux3_iattr_data *idata = bufvec->idata;
	struct page *page, *prev_page;
	struct buffer_head *buffer;
	pgoff_t outside_index;

	outside_index = (idata->i_size+(PAGE_CACHE_SIZE-1)) >> PAGE_CACHE_SHIFT;

	buffer = buffers_entry(bufvec->buffers->next);
	page = prev_page = buffer->b_page;
	lock_page(page);
	while (1) {
		trace("cancel dirty: buffer %p, block %Lu",
		      buffer, bufindex(buffer));

		/* Cancel buffer dirty of outside i_size */
		list_del_init(&buffer->b_assoc_buffers);
		tux3_clear_buffer_dirty_for_io(buffer, sb, 0);
		tux3_clear_buffer_dirty_for_io_hack(buffer);

		if (list_empty(bufvec->buffers))
			break;

		buffer = buffers_entry(bufvec->buffers->next);
		if (buffer->b_page != prev_page) {
			bufvec_cancel_and_unlock_page(page, outside_index);

			prev_page = page;
			page = buffer->b_page;
			lock_page(page);
		}
	}
	bufvec_cancel_and_unlock_page(page, outside_index);
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
	unsigned contig_count = bufvec_contig_count(bufvec);

	if (contig_count) {
		block_t last;

		/* Check contig_count limit */
		if (bufvec_contig_count(bufvec) == MAX_BUFVEC_COUNT)
			return 0;

		/* Check if buffer is logically contiguous */
		last = bufvec_contig_last_index(bufvec);
		if (last != bufindex(buffer) - 1)
			return 0;
	}

	bufvec_buffer_move_to_contig(bufvec, buffer);

	return 1;
}

/*
 * Try to collect logically contiguous dirty range from bufvec->buffers.
 *
 * return value:
 * 1 - there is buffers for I/O
 * 0 - no buffers for I/O
 */
static int bufvec_contig_collect(struct bufvec *bufvec)
{
	struct sb *sb = tux_sb(bufvec_inode(bufvec)->i_sb);
	struct tux3_iattr_data *idata = bufvec->idata;
	struct buffer_head *buffer;
	block_t last_index, next_index, outside_block;

	/* If there is in-progress contiguous range, leave as is */
	if (bufvec_contig_count(bufvec))
		return 1;
	assert(!list_empty(bufvec->buffers));

	outside_block = (idata->i_size + sb->blockmask) >> sb->blockbits;

	buffer = buffers_entry(bufvec->buffers->next);
	next_index = bufindex(buffer);
	/* If next buffer is fully outside i_size, clear dirty */
	if (next_index >= outside_block) {
		bufvec_cancel_dirty_outside(bufvec);
		return 0;
	}

	do {
		/* Check contig_count limit */
		if (bufvec_contig_count(bufvec) == MAX_BUFVEC_COUNT)
			break;
		bufvec_buffer_move_to_contig(bufvec, buffer);
		trace("buffer %p", buffer);

		if (list_empty(bufvec->buffers))
			break;

		buffer = buffers_entry(bufvec->buffers->next);
		last_index = next_index;
		next_index = bufindex(buffer);

		/* If next buffer is fully outside i_size, clear dirty */
		if (next_index >= outside_block) {
			bufvec_cancel_dirty_outside(bufvec);
			break;
		}
	} while (last_index == next_index - 1);

	return !!bufvec_contig_count(bufvec);
}

static int buffer_index_cmp(void *priv, struct list_head *a,
			    struct list_head *b)
{
	struct buffer_head *buf_a, *buf_b;

	buf_a = list_entry(a, struct buffer_head, b_assoc_buffers);
	buf_b = list_entry(b, struct buffer_head, b_assoc_buffers);

	/*
	 * Optimized version of the following:
	 *
	 * if (bufindex(buf_a) < bufindex(buf_b))
	 *	return -1;
	 * else if (bufindex(buf_a) > bufindex(buf_b))
	 *	return 1;
	 */
	if (buf_a->b_page->index < buf_b->b_page->index)
		return -1;
	else if (buf_a->b_page->index > buf_b->b_page->index)
		return 1;
	else {
		/* page_offset() is same, compare offset within page */
		if (buf_a->b_data < buf_b->b_data)
			return -1;
		if (buf_a->b_data > buf_b->b_data)
			return 1;
	}

	return 0;
}

/*
 * Flush buffers in head
 */
int flush_list(struct inode *inode, struct tux3_iattr_data *idata,
	       struct list_head *head, int req_flag)
{
	struct bufvec bufvec;
	int err = 0;

	/* FIXME: on error path, we have to do something for buffer state */

	if (list_empty(head))
		return 0;

	bufvec_init(&bufvec, mapping(inode), head, idata);

	/* Sort by bufindex() */
	list_sort(NULL, head, buffer_index_cmp);

	while (bufvec_next_buffer_page(&bufvec)) {
		/* Collect contiguous buffer range */
		if (bufvec_contig_collect(&bufvec)) {
			/* Start I/O */
			err = tux_inode(inode)->io(WRITE | req_flag, &bufvec);
			if (err)
				break;
		}
	}

	bufvec_free(&bufvec);

	return err;
}

/*
 * I/O helper for physical index buffers (e.g. buffers on volmap)
 */
int __tux3_volmap_io(int rw, struct bufvec *bufvec, block_t physical,
		     unsigned count)
{
	return blockio_vec(rw, bufvec, physical, count);
}

int tux3_volmap_io(int rw, struct bufvec *bufvec)
{
	block_t physical = bufvec_contig_index(bufvec);
	unsigned count = bufvec_contig_count(bufvec);

	/* FIXME: For now, this is only for write */
	assert(rw & WRITE);

	return __tux3_volmap_io(rw, bufvec, physical, count);
}
