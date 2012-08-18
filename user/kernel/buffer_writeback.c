/*
 * Write back buffers
 */

/*
 * Helper for buffer vector I/O.
 */

/* Initialize bufvec */
static void bufvec_init(struct bufvec *bufvec)
{
	INIT_LIST_HEAD(&bufvec->buffers);
	bufvec->count = 0;
	bufvec->bio = NULL;
}

static void bufvec_free(struct bufvec *bufvec)
{
	/* FIXME: on error path, this will happens */
	assert(list_empty(&bufvec->buffers));
	assert(bufvec->bio == NULL);
	bufvec_init(bufvec);
}

/*
 * Add buffer to bufvec. If it is not logically contiguous, return 0
 * and fail to add.
 *
 * return value:
 * 0 - failed to add
 * 1 - success
 */
static int bufvec_add(struct bufvec *bufvec, struct buffer_head *buffer)
{
	/* Check if buffer is logically contiguous */
	if (bufvec_count(bufvec)) {
		block_t last = bufvec_last_index(bufvec);
		if (last != bufindex(buffer) - 1)
			return 0;
	}

	/*
	 * This is called by backend, it means buffer state should be
	 * stable. So, we don't need lock for buffer state list
	 * (->b_assoc_buffers).
	 * FIXME: above is true?
	 */
	list_move_tail(&buffer->b_assoc_buffers, &bufvec->buffers);
	buffer->b_assoc_map = NULL;
	trace("buffer %p", buffer);

	bufvec->count++;

	return 1;
}

/*
 * Special purpose single pointer list (FIFO order) for buffers on bio
 */
static struct buffer_head *bufvec_bio_add_buffer(struct bio *bio,
			struct buffer_head *last, struct buffer_head *new)
{
	new->b_private = NULL;

	if (last)
		last->b_private = new;
	else
		bio->bi_private = new;

	return new;
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

/*
 * bio completion for bufvec based I/O
 */
static void bufvec_end_io(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	char b[BDEVNAME_SIZE];

	trace("bio %p, err %d", bio, err);

	/* Remove buffer from bio, then unlock buffer */
	while (1) {
		struct buffer_head *buffer = bufvec_bio_del_buffer(bio);
		if (!buffer)
			break;

		if (uptodate)
			set_buffer_uptodate(buffer);
		else {
			if (!test_bit(BIO_QUIET, &bio->bi_flags)) {
				printk(KERN_WARNING "lost page write due to "
				       "I/O error on %s\n",
				       bdevname(buffer->b_bdev, b));
			}
			set_buffer_write_io_error(buffer);
			clear_buffer_uptodate(buffer);
		}
		trace("buffer %p", buffer);
		unlock_buffer(buffer);
		put_bh(buffer);
	}

	bio_put(bio);
}

static struct bio *bufvec_bio_alloc(struct inode *inode, unsigned count)
{
	gfp_t gfp_flags = GFP_NOFS;
	struct bio *bio;

	count = min_t(unsigned, count, bio_get_nr_vecs(inode->i_sb->s_bdev));
	bio = bio_alloc(gfp_flags, count);
	/* This retry is from mpage_alloc() */
	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (count /= 2))
			bio = bio_alloc(gfp_flags, count);
	}

	return bio;
}

/*
 * Preparation for I/O. I.e. change buffer state for I/O, prepare
 * bio, and link associated buffers to bio.
 *
 * This doesn't guarantee all candidate buffers are prepared for
 * I/O. It might be limited by device or block layer.
 *
 * return value:
 * < 0 - error
 * > 0 - buffer count to be prepared
 */
int bufvec_prepare_io(struct bufvec *bufvec, block_t physical, unsigned count)
{
	struct inode *inode;
	struct bio *bio;
	struct buffer_head *last = NULL;
	unsigned i;

	assert(bufvec->bio == NULL);
	assert(bufvec->count >= count);

	inode = buffer_inode(bufvec_first_buf(bufvec));

	bio = bufvec_bio_alloc(inode, count);
	if (bio == NULL)
		return -ENOMEM;

	bufvec->bio = bio;
	bio->bi_bdev = inode->i_sb->s_bdev;
	bio->bi_sector = physical << (tux_sb(inode->i_sb)->blockbits - 9);
	bio->bi_end_io = bufvec_end_io;

	/* Add buffers to bio */
	for (i = 0; i < count; i++) {
		/* Buffer locking order for I/O is lower index to
		 * bigger index. And grouped by inode. FIXME: is this sane? */
		struct buffer_head *buffer = bufvec_first_buf(bufvec);
		struct page *page = buffer->b_page;
		unsigned int length = bufsize(buffer);
		unsigned int offset = bh_offset(buffer);

		if (bio_add_page(bio, page, length, offset) < length)
			break;

		bufvec->count--;

		/* FIXME: need lock? (buffer is already owned by backend...) */
		list_del_init(&buffer->b_assoc_buffers);

		lock_buffer(buffer);
		if (!test_clear_buffer_dirty(buffer)) {
			unlock_buffer(buffer);
			continue;
		}
		get_bh(buffer);
		last = bufvec_bio_add_buffer(bio, last, buffer);
		trace("buffer %p", buffer);
	}
	assert(i > 0);

	return i;
}

/*
 * Flush buffers in head
 */
int flush_list(struct list_head *head)
{
	return 0;
}
