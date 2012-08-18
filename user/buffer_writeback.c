/*
 * Write back buffers
 */

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
 * Helper for buffer vector I/O.
 */

#define buffers_entry(x) \
	list_entry(x, struct buffer_head, link)

/* Initialize bufvec */
void bufvec_init(struct bufvec *bufvec, struct list_head *head)
{
	INIT_LIST_HEAD(&bufvec->contig);
	INIT_LIST_HEAD(&bufvec->for_io);
	bufvec->buffers		= head;
	bufvec->contig_count	= 0;
	bufvec->end_io		= NULL;
}

void bufvec_free(struct bufvec *bufvec)
{
	/* FIXME: on error path, this will happens */
	assert(!bufvec->buffers || list_empty(bufvec->buffers));
	assert(list_empty(&bufvec->contig));
	assert(list_empty(&bufvec->for_io));
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

	list_move_tail(&buffer->link, &bufvec->contig);
	bufvec->contig_count++;

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

	buffer = buffers_entry(bufvec->buffers->next);
	do {
		list_move_tail(&buffer->link, &bufvec->contig);
		bufvec->contig_count++;

		if (list_empty(bufvec->buffers))
			break;

		last_index = bufindex(buffer);
		buffer = buffers_entry(bufvec->buffers->next);
	} while (last_index == bufindex(buffer) - 1);
}

static void bufvec_io_done(struct bufvec *bufvec, int err)
{
	struct list_head *head = &bufvec->for_io;

	while (!list_empty(head)) {
		struct buffer_head *buffer = buffers_entry(head->next);
		list_del_init(&buffer->link);
		bufvec->end_io(buffer, err);
	}
}

/*
 * Prepare and submit I/O for specified range.
 *
 * This doesn't guarantee all candidate buffers are prepared for
 * I/O. It might be limited by device or block layer.
 *
 * return value:
 * < 0 - error
 *   0 - success
 */
int bufvec_io(int rw, struct bufvec *bufvec, block_t physical, unsigned count)
{
	struct sb *sb;
	struct iovec *iov;
	unsigned i, iov_count;
	int err;

	assert(count <= bufvec_contig_count(bufvec));

	iov = malloc(sizeof(*iov) * count);
	if (iov == NULL)
		return -ENOMEM;
	iov_count = 0;

	sb = tux_sb(buffer_inode(bufvec_contig_buf(bufvec))->i_sb);

	/* Add buffers for I/O */
	for (i = 0; i < count; i++) {
		struct buffer_head *buffer = bufvec_contig_buf(bufvec);

		/* buffer will be re-added into per-state list after I/O done */
		list_move_tail(&buffer->link, &bufvec->for_io);
		bufvec->contig_count--;

		iov[i].iov_base = bufdata(buffer);
		iov[i].iov_len = bufsize(buffer);
		iov_count++;
	}
	assert(i > 0);

	err = devio_vec(rw, sb_dev(sb), physical << sb->blockbits,
			iov, iov_count);
	bufvec_io_done(bufvec, err);

	free(iov);

	return 0;
}

/*
 * Call completion without I/O. I.e. change buffer state without I/O.
 */
void bufvec_complete_without_io(struct bufvec *bufvec, unsigned count)
{
	unsigned i;

	assert(count <= bufvec_contig_count(bufvec));

	/* Add buffers for completion */
	for (i = 0; i < count; i++) {
		struct buffer_head *buffer = bufvec_contig_buf(bufvec);

		/* buffer will be re-added into per-state list after I/O done */
		list_move_tail(&buffer->link, &bufvec->for_io);
		bufvec->contig_count--;
	}
	assert(i > 0);

	bufvec_io_done(bufvec, 0);
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

/*
 * Flush buffers in head
 */
int flush_list(struct list_head *head)
{
	struct bufvec bufvec;
	map_t *map;
	int err = 0;

	/* FIXME: on error path, we have to do something for buffer state */

	if (list_empty(head))
		return 0;

	bufvec_init(&bufvec, head);

	/* Sort by bufindex() */
	list_sort(NULL, head, buffer_index_cmp);

	/* Use first buffer to get inode, all should be for this inode. */
	map = buffer_inode(buffers_entry(head->next))->map;

	while (!list_empty(head)) {
		/* Collect contiguous buffer range */
		bufvec_contig_collect(&bufvec);

		/* Start I/O */
		err = map->io(WRITE, &bufvec);
		if (err)
			break;
	}

	bufvec_free(&bufvec);

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
