/*
 * Copied some block library functions, to replace mark_buffer_dirty()
 * by temp_blockdirty(), to replace discard_buffer() by
 * tux3_invalidate_buffer(), and add tux3_iattrdirty().
 *
 * We should check the update of original functions, and sync with it.
 */

#include <linux/pagevec.h>

static void temp_blockdirty(struct buffer_head *buffer)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);

	assert(buffer_can_modify(buffer, sb->delta));

	tux3_set_buffer_dirty(mapping(inode), buffer, sb->delta);
	/* FIXME: we need to dirty inode only if buffer became
	 * dirty. However, tux3_set_buffer_dirty doesn't provide it */
	__tux3_mark_inode_dirty(inode, I_DIRTY_PAGES);
}

/* Copy of page_zero_new_buffers() (changed to call temp_blockdirty()) */
static void tux3_page_zero_new_buffers(struct page *page, unsigned from,
				       unsigned to)
{
	unsigned int block_start, block_end;
	struct buffer_head *head, *bh;

	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		return;

	bh = head = page_buffers(page);
	block_start = 0;
	do {
		block_end = block_start + bh->b_size;

		if (buffer_new(bh)) {
			if (block_end > from && block_start < to) {
				if (!PageUptodate(page)) {
					unsigned start, size;

					start = max(from, block_start);
					size = min(to, block_end) - start;

					zero_user(page, start, size);
					set_buffer_uptodate(bh);
				}

				clear_buffer_new(bh);
				temp_blockdirty(bh);
			}
		}

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
}

/*
 * Copy of __block_write_begin() (changed to call temp_blockdirty(),
 * and to remove unmap_underlying_metadata())
 */
static int __tux3_write_begin(struct page *page, loff_t pos, unsigned len,
			      get_block_t *get_block)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	blocksize = 1 << inode->i_blkbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	bbits = inode->i_blkbits;
	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);

	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				break;
			if (buffer_new(bh)) {
#if 0
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
#endif
				if (PageUptodate(page)) {
					/* FIXME: do we have to mark this dirty?
					 * re-think after mmap support */
					//clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					//temp_blockdirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page,
						to, block_end,
						block_start, from);
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue;
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		     (block_start < from || block_end > to)) {
			ll_rw_block(READ, 1, &bh);
			*wait_bh++=bh;
		}
	}
	/*
	 * If we issued read requests - let them complete.
	 */
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		tux3_page_zero_new_buffers(page, from, to);
	return err;
}

/* Copy of block_write_begin() */
static int tux3_write_begin(struct address_space *mapping, loff_t pos,
			    unsigned len, unsigned flags,
			    struct page **pagep, get_block_t *get_block)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int status;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	assert(!PageForked(page));	/* FIXME: handle forked page */

	status = __tux3_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		page_cache_release(page);
		page = NULL;
	}

	*pagep = page;
	return status;
}

/* Copy of __block_commit_write() (changed to call temp_blockdirty()) */
static int __tux3_commit_write(struct inode *inode, struct page *page,
			       unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	blocksize = 1 << inode->i_blkbits;

	for(bh = head = page_buffers(page), block_start = 0;
	    bh != head || !block_start;
	    block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
			temp_blockdirty(bh);
		}
		clear_buffer_new(bh);
	}

	/*
	 * If this is a partial write which happened to make all buffers
	 * uptodate then we can optimize away a bogus readpage() for
	 * the next read(). Here we 'discover' whether the page went
	 * uptodate as a result of this (potentially partial) write.
	 */
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/* Copy of block_write_end() */
static int __tux3_write_end(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned copied,
			    struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start;

	start = pos & (PAGE_CACHE_SIZE - 1);

	if (unlikely(copied < len)) {
		/*
		 * The buffers that were written will now be uptodate, so we
		 * don't have to worry about a readpage reading them and
		 * overwriting a partial write. However if we have encountered
		 * a short write and only partially written into a buffer, it
		 * will not be marked uptodate, so a readpage might come in and
		 * destroy our partial write.
		 *
		 * Do the simplest thing, and just treat any short write to a
		 * non uptodate page as a zero-length write, and force the
		 * caller to redo the whole thing.
		 */
		if (!PageUptodate(page))
			copied = 0;

		tux3_page_zero_new_buffers(page, start+copied, start+len);
	}
	flush_dcache_page(page);

	/* This could be a short (even 0-length) commit */
	__tux3_commit_write(inode, page, start, start+copied);

	return copied;
}

/* Copy of generic_write_end() (added tux3_iattrdirty()) */
static int tux3_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	int i_size_changed = 0;

	copied = __tux3_write_end(file, mapping, pos, len, copied, page, fsdata);

	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 *
	 * But it's important to update i_size while still holding page lock:
	 * page writeout could otherwise come in and zero beyond i_size.
	 */
	if (pos+copied > inode->i_size) {
		tux3_iattrdirty(inode);
		i_size_write(inode, pos+copied);
		i_size_changed = 1;
	}

	unlock_page(page);
	page_cache_release(page);

	/*
	 * Don't mark the inode dirty under page lock. First, it unnecessarily
	 * makes the holding time of page lock longer. Second, it forces lock
	 * ordering of page lock and transaction start for journaling
	 * filesystems.
	 */
	if (i_size_changed)
		tux3_mark_inode_dirty(inode);

	return copied;
}

/* Copy of block_invalidatepage() (changed to call tux3_invalidate_buffer()) */
static void tux3_invalidatepage(struct page *page, unsigned long offset)
{
	struct buffer_head *head, *bh, *next;
	unsigned int curr_off = 0;

	BUG_ON(!PageLocked(page));
	/* If there is no buffer, buffers shouldn't be dirty */
	if (!page_has_buffers(page))
		goto out;

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		/*
		 * is this block fully invalidated?
		 */
		if (offset <= curr_off)
			tux3_invalidate_buffer(bh);
		curr_off = next_off;
		bh = next;
	} while (bh != head);

	/*
	 * We release buffers only if the entire page is being invalidated.
	 * The get_block cached value has been unconditionally invalidated,
	 * so real IO is not possible anymore.
	 */
	if (offset == 0)
		try_to_release_page(page, 0);
out:
	return;
}

/* Copy of block_truncate_page() (changed to call temp_blockdirty()) */
int tux3_truncate_page(struct address_space *mapping,
		       loff_t from, get_block_t *get_block)
{
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize;
	sector_t iblock;
	unsigned length, pos;
	struct inode *inode = mapping->host;
	struct page *page;
	struct buffer_head *bh;
	int err;

	blocksize = 1 << inode->i_blkbits;
	length = offset & (blocksize - 1);

	/* Block boundary? Nothing to do */
	if (!length)
		return 0;

	length = blocksize - length;
	iblock = (sector_t)index << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	page = grab_cache_page(mapping, index);
	err = -ENOMEM;
	if (!page)
		goto out;
	assert(!PageForked(page));	/* FIXME: handle forked page */

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	err = 0;
	if (!buffer_mapped(bh)) {
		WARN_ON(bh->b_size != blocksize);
		err = get_block(inode, iblock, bh, 0);
		if (err)
			goto unlock;
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh))
			goto unlock;
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh) && !buffer_delay(bh) && !buffer_unwritten(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
	}

	zero_user(page, offset, length);
	temp_blockdirty(bh);
	err = 0;

unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return err;
}

/*
 * Copy of truncate_inode_pages_range()
 *
 * Changes:
 * - to call bufferfork_to_invalidate() before invalidate buffers
 * - remove to wait the page under I/O (we do buffer fork instead)
 *
 * FIXME: some functions are not exported to implement own
 * truncate_inode_pages_page() fully. So this just do the buffer fork,
 * without invalidate. This way is inefficient, and we would want to merge
 * tux3_truncate_inode_pages_page() and truncate_inode_pages_range().
 */
void tux3_truncate_inode_pages_range(struct address_space *mapping,
				     loff_t lstart, loff_t lend)
{
	const pgoff_t start = (lstart + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
#if 0
	const unsigned partial = lstart & (PAGE_CACHE_SIZE - 1);
#endif
	struct pagevec pvec;
	pgoff_t index;
	pgoff_t end;
	int i;

#if 0 /* FIXME */
	cleancache_invalidate_inode(mapping);
#endif
	if (mapping->nrpages == 0)
		return;

	BUG_ON((lend & (PAGE_CACHE_SIZE - 1)) != (PAGE_CACHE_SIZE - 1));
	end = (lend >> PAGE_CACHE_SHIFT);

	pagevec_init(&pvec, 0);
	index = start;
	while (index <= end && pagevec_lookup(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE - 1) + 1)) {
#if 0 /* FIXME */
		mem_cgroup_uncharge_start();
#endif
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			/* We rely upon deletion not changing page->index */
			index = page->index;
			if (index > end)
				break;

			if (!trylock_page(page))
				continue;
			WARN_ON(page->index != index);
#if 0
			if (PageWriteback(page)) {
				unlock_page(page);
				continue;
			}
#endif
			bufferfork_to_invalidate(mapping, page);
			unlock_page(page);
		}
		pagevec_release(&pvec);
#if 0 /* FIXME */
		mem_cgroup_uncharge_end();
#endif
		cond_resched();
		index++;
	}
#if 0
	/* Partial page is handled on tux3_truncate_page() */
	if (partial) {
		struct page *page = find_lock_page(mapping, start - 1);
		if (page) {
			wait_on_page_writeback(page);
			tux3_truncate_partial_page(page, partial);
			unlock_page(page);
			page_cache_release(page);
		}
	}
#endif
	index = start;
	for ( ; ; ) {
		cond_resched();
		if (!pagevec_lookup(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE - 1) + 1)) {
#if 0
			if (index == start)
				break;
			index = start;
			continue;
#else
			/*
			 * We leave the pages as is if it can be invalidated.
			 * And we don't need check the same page repeatedly.
			 */
			break;
#endif
		}
		if (index == start && pvec.pages[0]->index > end) {
			pagevec_release(&pvec);
			break;
		}
#if 0 /* FIXME */
		mem_cgroup_uncharge_start();
#endif
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			/* We rely upon deletion not changing page->index */
			index = page->index;
			if (index > end)
				break;

			lock_page(page);
			WARN_ON(page->index != index);
#if 0
			wait_on_page_writeback(page);
#endif
			bufferfork_to_invalidate(mapping, page);
			unlock_page(page);
		}
		pagevec_release(&pvec);
#if 0 /* FIXME */
		mem_cgroup_uncharge_end();
#endif
		index++;
	}
#if 0 /* FIXME */
	cleancache_invalidate_inode(mapping);
#endif
}
