/*
 * Copied some block library functions, to replace mark_buffer_dirty()
 * by pagefork_for_blockdirty() and __tux3_mark_buffer_dirty(),
 * to replace discard_buffer() by tux3_invalidate_buffer(), and add
 * tux3_iattrdirty().
 *
 * We should check the update of original functions, and sync with it.
 */

#include <linux/pagevec.h>
#include <linux/cleancache.h>

/*
 * Copy of page_zero_new_buffers()
 * (changed to call __tux3_mark_buffer_dirty())
 */
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
				unsigned delta = tux3_get_current_delta();

				if (!PageUptodate(page)) {
					unsigned start, size;

					start = max(from, block_start);
					size = min(to, block_end) - start;

					zero_user(page, start, size);
					set_buffer_uptodate(bh);
				}

				clear_buffer_new(bh);
				__tux3_mark_buffer_dirty(bh, delta);
			}
		}

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
}

/*
 * Copy of __block_write_begin() (changed to call __tux3_mark_buffer_dirty(),
 * and to remove unmap_underlying_metadata())
 */
static int __tux3_write_begin(struct page *page, loff_t pos, unsigned len,
			      get_block_t *get_block)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	struct sb *sb = tux_sb(inode->i_sb);
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	/* Use blocksize/blockbits in sb, instead of inode->i_blkbits */
	blocksize = sb->blocksize;
	bbits = sb->blockbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

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
			/*
			 * FIXME: If user overwrites block fully, we
			 * don't need get_block(). Since we know it is
			 * delayed allocation, so, we can use SEG_HOLE
			 * as delayed allocation.
			 */
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
					//__tux3_mark_buffer_dirty(bh, delta);
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

/*
 * Copy of block_write_begin()
 * (Add to call pagefork_for_blockdirty() for buffer fork)
 */
static int tux3_write_begin(struct address_space *mapping, loff_t pos,
			    unsigned len, unsigned flags,
			    struct page **pagep, get_block_t *get_block,
			    int check_fork)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int status;

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	/*
	 * FIXME: If check_fork == 0, caller handle buffer fork.
	 * Unlike check_fork hack, we are better to provide the different
	 * blockget() implementation doesn't use tux3_write_begin().
	 */
	if (check_fork) {
		struct page *tmp;

		tmp = pagefork_for_blockdirty(page, tux3_get_current_delta());
		if (IS_ERR(tmp)) {
			int err;
			unlock_page(page);
			page_cache_release(page);

			err = PTR_ERR(tmp);
			if (err == -EAGAIN)
				goto retry;
			return err;
		}
		page = tmp;
	}

	status = __tux3_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		page_cache_release(page);
		page = NULL;
	}

	*pagep = page;
	return status;
}

/*
 * Copy of __block_commit_write()
 * (changed to call __tux3_mark_buffer_dirty())
 */
static int __tux3_commit_write(struct inode *inode, struct page *page,
			       unsigned from, unsigned to)
{
	unsigned delta = tux3_get_current_delta();
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	blocksize = bh->b_size;

	block_start = 0;
	do {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
			__tux3_mark_buffer_dirty(bh, delta);
		}
		clear_buffer_new(bh);

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

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

/*
 * Check if we can cancel the dirty of page. This is called after
 * clear dirty of buffers on this page.
 *
 * This would be called for similar purpose to tux3_invalidatepage(),
 * but caller care to change buffer state.
 *
 * FIXME: this traverse buffers on page for each clear dirty
 * buffer. We may want to clear dirty page as batch job (like
 * ->writepages())
 * FIXME: cancel dirty is untested for mmap write.
 *
 * Caller must care locking (e.g. volmap page in backend, hold lock_page()).
 */
void tux3_try_cancel_dirty_page(struct page *page)
{
	struct buffer_head *tmp, *head;

	tmp = head = page_buffers(page);
	do {
		if (buffer_dirty(tmp))
			return;

		tmp = tmp->b_this_page;
	} while (tmp != head);

	cancel_dirty_page(page, PAGE_CACHE_SIZE);
}

/*
 * Based on block_invalidatepage().
 * (changed to call tux3_invalidate_buffer(), and if no dirty buffers,
 * cancel dirty page)
 *
 * This invalidate the buffers on page. Then if there is no dirty
 * buffers, cancel dirty page.
 *
 * FIXME: cancel dirty is untested for mmap write.
 *
 * Caller must hold lock_page().
 */
static void tux3_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int curr_off = 0;
	unsigned int stop = length + offset;
	int has_dirty = 0;

	BUG_ON(!PageLocked(page));
	/* If there is no buffer, buffers shouldn't be dirty */
	if (!page_has_buffers(page))
		goto out;

	/*
	 * Check for overflow
	 */
	BUG_ON(stop > PAGE_CACHE_SIZE || stop < length);

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		/* Are we still fully in range ? */
		if (next_off <= stop) {
			/* Is this block fully invalidated? */
			if (offset <= curr_off)
				tux3_invalidate_buffer(bh);
		}

		/* If buffer is dirty, don't cancel dirty page */
		if (buffer_dirty(bh))
			has_dirty = 1;

		curr_off = next_off;
		bh = next;
	} while (bh != head);

	if (!has_dirty)
		cancel_dirty_page(page, length);

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

/*
 * Based on block_truncate_page()
 * (changed to call pagefork_for_blockdirty() and __tux3_mark_buffer_dirty()())
 *
 * This fills zero for whole page, and checks if buffer can be truncated.
 * Then invalidate buffers if it is needed.
 *
 * Even if truncate was block boundary, we may have to fork page.  If
 * the buffers are dirtied for past delta, we can't truncate, so this
 * forks buffer in that case.
 */
static int __tux3_truncate_partial_block(struct address_space *mapping,
					 loff_t from, get_block_t *get_block)
{
	struct inode *inode = mapping->host;
	struct sb *sb = tux_sb(inode->i_sb);
	unsigned delta = tux3_get_current_delta();
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE - 1);
	sector_t iblock;
	unsigned pos, invalid_from;
	struct page *page, *tmp;
	struct buffer_head *bh = NULL;
	int err, forked;

	/* Page boundary? */
	if (!offset)
		return 0;

	iblock = from >> sb->blockbits;
	pos = offset >> sb->blockbits;
	invalid_from = offset;

	/*
	 * Block boundary? Make sure the buffers can be truncated.
	 */
	if (!(offset & sb->blockmask)) {
		/*
		 * If there is dirty buffers outside i_size, we have
		 * to zero fill those. To do it, we need buffer fork
		 * to make stable page on in-flight delta.
		 *
		 * NOTE: Zeroed buffers are not needed to be written
		 * though, we have to provide the data on page for
		 * frontend until data on forked page is available via
		 * dtree.  So, this dirty the buffer to pin the page.
		 *
		 * FIXME: This dirty buffer outside i_size is not
		 * needed to be written, if buffer is outside i_size,
		 * buffer is not written. Although if buffer became
		 * inside i_size on this delta, zeroed buffer can be
		 * written out.  This is unnecessary writeout.
		 *
		 * FIXME: If we didn't need buffer fork, we don't need
		 * to dirty buffer.
		 */
retry_find:
		page = find_lock_page(mapping, index);
		if (page) {
			tmp = pagefork_for_blockdirty(page, delta);
			if (IS_ERR(tmp)) {
				unlock_page(page);
				page_cache_release(page);

				err = PTR_ERR(tmp);
				if (err == -EAGAIN)
					goto retry_find;
				goto out;
			}
			forked = tmp != page;
			page = tmp;

dirty_buffer_outside:
			/* If no buffer fork, we don't need to pin the page */
			/* FIXME: might be forked in previous truncate,
			 * so dirty unconditionally */
			forked = 1;
			if (forked && page_has_buffers(page)) {
				assert(page_has_buffers(page));
				/* Dirty outside i_size to pin the page */
				bh = __get_buffer(page, pos);
				__tux3_mark_buffer_dirty(bh, delta);

				invalid_from = (pos + 1) << sb->blockbits;
				invalid_from &= PAGE_CACHE_SIZE - 1;
			}

			goto zero_fill_page;
		}

		/* No page, do nothing */
		return 0;
	}

retry_grab:
	page = grab_cache_page(mapping, index);
	err = -ENOMEM;
	if (!page)
		goto out;

	tmp = pagefork_for_blockdirty(page, delta);
	if (IS_ERR(tmp)) {
		unlock_page(page);
		page_cache_release(page);

		err = PTR_ERR(tmp);
		if (err == -EAGAIN)
			goto retry_grab;
		goto out;
	}
	forked = tmp != page;
	page = tmp;

	if (!page_has_buffers(page))
		create_empty_buffers(page, sb->blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = __get_buffer(page, pos);

	err = 0;
	/*
	 * FIXME: If this buffer is dirty, we would not need to call
	 * get_block()?
	 */
	if (!buffer_mapped(bh)) {
		WARN_ON(bh->b_size != sb->blocksize);
		err = get_block(inode, iblock, bh, 0);
		if (err)
			goto unlock;
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh)) {
			/*
			 * If this is hole and partial truncate is not
			 * last block on the page, we have to check
			 * whether the page needs buffer fork or not.
			 */
			if (pos + 1 < PAGE_CACHE_SIZE >> sb->blockbits) {
				pos++;
				goto dirty_buffer_outside;
			}
			goto unlock;
		}
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

	__tux3_mark_buffer_dirty(bh, delta);
	/*
	 * FIXME: If we did buffer fork, the other buffers should be
	 * clean, so we don't need to invalidate buffers outside
	 * i_size.
	 */

zero_fill_page:
	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	cleancache_invalidate_page(mapping, page);
	if (invalid_from && page_has_buffers(page)) {
		mapping->a_ops->invalidatepage(page, invalid_from,
					       PAGE_CACHE_SIZE - invalid_from);
	}

	err = 0;

unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return err;
}

/* Truncate partial block. If partial, we have to update last block. */
int tux3_truncate_partial_block(struct inode *inode, loff_t newsize)
{
	return __tux3_truncate_partial_block(inode->i_mapping, newsize,
					     tux3_get_block);
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
	pgoff_t		start;		/* inclusive */
	pgoff_t		end;		/* exclusive */
	unsigned int	partial_start;	/* inclusive */
	unsigned int	partial_end;	/* exclusive */
	struct pagevec	pvec;
	pgoff_t		index;
	int		i;

#if 0 /* FIXME */
	cleancache_invalidate_inode(mapping);
#endif
	if (mapping->nrpages == 0)
		return;

	/* FIXME: should use MAX_LFS_FILESIZE, instead of -1 */
	if (lend == -1 || lend > MAX_LFS_FILESIZE)
		lend = MAX_LFS_FILESIZE;
	/* Caller must check maximum size, otherwrite pgoff_t can overflow */
	BUG_ON(lstart > MAX_LFS_FILESIZE);

	/* Offsets within partial pages */
	partial_start = lstart & (PAGE_CACHE_SIZE - 1);
	partial_end = (lend + 1) & (PAGE_CACHE_SIZE - 1);

	/*
	 * 'start' and 'end' always covers the range of pages to be fully
	 * truncated. Partial pages are covered with 'partial_start' at the
	 * start of the range and 'partial_end' at the end of the range.
	 * Note that 'end' is exclusive while 'lend' is inclusive.
	 */
	start = ((u64)lstart + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	end = ((u64)lend + 1) >> PAGE_CACHE_SHIFT;

	pagevec_init(&pvec, 0);
	index = start;
	while (index < end && pagevec_lookup(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE))) {
#if 0 /* FIXME */
		mem_cgroup_uncharge_start();
#endif
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			/* We rely upon deletion not changing page->index */
			index = page->index;
			if (index >= end)
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
	if (partial_start) {
		struct page *page = find_lock_page(mapping, start - 1);
		if (page) {
			unsigned int top = PAGE_CACHE_SIZE;
			if (start > end) {
				/* Truncation within a single page */
				top = partial_end;
				partial_end = 0;
			}
			wait_on_page_writeback(page);
			tux3_truncate_partial_page(page, partial_start, top);
			unlock_page(page);
			page_cache_release(page);
		}
	}
	if (partial_end) {
		struct page *page = find_lock_page(mapping, end);
		if (page) {
			wait_on_page_writeback(page);
			tux3_truncate_partial_page(page, 0, partial_end);
			unlock_page(page);
			page_cache_release(page);
		}
	}
#endif
	/*
	 * If the truncation happened within a single page no pages
	 * will be released, just zeroed, so we can bail out now.
	 */
	if (start >= end)
		return;

	index = start;
	for ( ; ; ) {
		cond_resched();
		if (!pagevec_lookup(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE))) {
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
		if (index == start && pvec.pages[0]->index >= end) {
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
			if (index >= end)
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
