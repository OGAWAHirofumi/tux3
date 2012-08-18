/*
 * Block Fork (Copy-On-Write of logically addressed block)
 */

#include <linux/hugetlb.h>	/* for PageHuge() */
#include <linux/swap.h>		/* for __lru_cache_add() */

#define PageForked(x)		PageChecked(x)
#define SetPageForked(x)	SetPageChecked(x)

static struct buffer_head *page_buffer(struct page *page, unsigned which)
{
	struct buffer_head *buffer = page_buffers(page);
	while (which--)
		buffer = buffer->b_this_page;
	return buffer;
}

/*
 * Check if the page can be modified for delta. I.e. All buffers
 * should be dirtied for delta, or clean.
 */
static int page_can_modify(struct buffer_head *buffer, unsigned delta)
{
	struct page *page = buffer->b_page;
	struct buffer_head *head;

	head = page_buffers(page);
	buffer = head;
	do {
		if (buffer_dirty(buffer) && !buffer_can_modify(buffer, delta))
			return 0;

		buffer = buffer->b_this_page;
	} while (buffer != head);

	return 1;
}

/* Based on migrate_page_copy() */
static struct page *clone_page(struct page *oldpage, unsigned blocksize)
{
	struct address_space *mapping = oldpage->mapping;
	gfp_t gfp_mask = mapping_gfp_mask(mapping) & ~__GFP_FS;
	struct page *newpage = __page_cache_alloc(gfp_mask);

	newpage->mapping = oldpage->mapping;
	newpage->index = oldpage->index;
	copy_highpage(newpage, oldpage);

	/* oldpage should be forked page */
	BUG_ON(PageForked(oldpage));

	/* FIXME: right? */
	BUG_ON(PageUnevictable(oldpage));
	BUG_ON(PageHuge(oldpage));
	if (PageError(oldpage))
		SetPageError(newpage);
	if (PageReferenced(oldpage))
		SetPageReferenced(newpage);
	if (PageUptodate(oldpage))
		SetPageUptodate(newpage);
	if (PageActive(oldpage))
		SetPageActive(newpage);
	if (PageMappedToDisk(oldpage))
		SetPageMappedToDisk(newpage);

#if 0	/* FIXME: need? */
	mlock_migrate_page(newpage, page);
	ksm_migrate_page(newpage, page);
#endif

	/* Lock newpage before visible via radix tree */
	assert(!PageLocked(newpage));
	__set_page_locked(newpage);

	create_empty_buffers(newpage, blocksize, 0);

	return newpage;
}

/* Schedule to add LRU list */
static void newpage_add_lru(struct page *page)
{
	if (TestClearPageActive(page))
		__lru_cache_add(page, LRU_ACTIVE_FILE);
	else
		__lru_cache_add(page, LRU_INACTIVE_FILE);
}

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
	struct page *oldpage = buffer->b_page;
	struct address_space *mapping = oldpage->mapping;
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);
	struct page *newpage;
	struct buffer_head *newbuf;
	void **pslot;

	trace("buffer %p, page %p, index %lx, count %u",
	      buffer, oldpage, oldpage->index, page_count(oldpage));
	trace("forked %u, dirty %u, writeback %u",
	      PageForked(oldpage), PageDirty(oldpage), PageWriteback(oldpage));

	/* The simple case: redirty on same delta */
	if (buffer_dirty(buffer) && buffer_can_modify(buffer, newdelta))
		return buffer;

	/* Take page lock to protect buffer list, and concurrent block_fork */
	lock_page(oldpage);

	/* This happens on partially dirty page. */
//	assert(PageUptodate(oldpage));

	/* Someone already forked this page. */
	if (PageForked(oldpage)) {
		buffer = ERR_PTR(-EAGAIN);
		goto out;
	}
	/* Page is under I/O, needs buffer fork */
	if (PageWriteback(oldpage))
		goto do_clone_page;
	/*
	 * If page isn't dirty (and isn't writeback), this is clean
	 * page (and all buffers should be clean on this page).  So we
	 * can just dirty the buffer for current delta.
	 */
	if (!PageDirty(oldpage)) {
		assert(!buffer_dirty(buffer));
		goto dirty_buffer;
	}

	/*
	 * (Re-)check the partial dirtied page under lock_page. (We
	 * don't allow the buffer has different delta states on same
	 * page.)
	 */
	if (buffer_dirty(buffer)) {
		/* Buffer is dirtied by newdelta, just modify this buffer */
		if (buffer_can_modify(buffer, newdelta))
			goto out;

		/* Buffer was dirtied by different delta, we need buffer fork */
	} else {
		/* Check other buffers sharing same page. */
		if (page_can_modify(buffer, newdelta)) {
			/* This page can be modified, dirty this buffer */
			goto dirty_buffer;
		}

		/* The page can't be modified for newdelta */
	}

do_clone_page:
	/* Clone the oldpage */
	newpage = clone_page(oldpage, sb->blocksize);
	if (IS_ERR(newpage)) {
		buffer = ERR_CAST(newpage);
		goto out;
	}

	newbuf = page_buffer(newpage, bh_offset(buffer) >> sb->blockbits);
	get_bh(newbuf);

	/*
	 * Similar to migrate_pages(), but the oldpage is for writeout.
	 * FIXME: we would have to add mmap handling (e.g. replace PTE)
	 */
#if 0 /* FIXME */
	charge = mem_cgroup_prepare_migration(oldpage, &mem);
#endif
	/* Replace page in radix tree. */
	spin_lock_irq(&mapping->tree_lock);
	/* The refcount to newpage is used for radix tree. */
	pslot = radix_tree_lookup_slot(&mapping->page_tree, oldpage->index);
	radix_tree_replace_slot(pslot, newpage);
	__inc_zone_page_state(newpage, NR_FILE_PAGES);
	__dec_zone_page_state(oldpage, NR_FILE_PAGES);
	/*
	 * Get refcount to oldpage.
	 * FIXME: The refcount of the oldpage is taken here, the
	 * refcount may not be needed actually. Because the oldpage is
	 * the dirty. Well, so, the backend has to free the oldpage.
	 * (page_cache_put(oldpage)).
	 */
	/* Referencer are radix-tree and ->private (+ readers). */
	trace("oldpage count %u", page_count(oldpage));
	assert(page_count(oldpage) >= 2);
	page_cache_get(oldpage);
	spin_unlock_irq(&mapping->tree_lock);
#if 0 /* FIXME */
	mem_cgroup_end_migration(mem, oldpage, newpage);
#endif
	newpage_add_lru(newpage);

	/*
	 * This prevents to re-fork the oldpage. And we guarantee the
	 * newpage is available on radix-tree here.
	 */
	SetPageForked(oldpage);
	unlock_page(oldpage);

	trace("cloned page %p, buffer %p", newpage, newbuf);
	brelse(buffer);
	buffer = newbuf;
	oldpage = newpage;

dirty_buffer:
	assert(!buffer_dirty(buffer));
	/* FIXME: we shouldn't open code this */
	tux3_set_buffer_dirty(buffer, newdelta);
	/* FIXME: we need to dirty inode only if buffer became
	 * dirty. However, tux3_set_buffer_dirty doesn't provide it */
	tux3_dirty_inode(buffer_inode(buffer), I_DIRTY_PAGES);

out:
	unlock_page(oldpage);

	return buffer;
}

#if 0
/* This must be called under the lock to serialize blockdirty() */
static int check_forked(struct page *page)
{
	return PageForked(page);
}

static void free_forked_page(struct page *page)
{
	assert(PageForked(page));
	/* vm may have refcount, so >= 3 (e.g. lru_add_pvecs) */
	assert(page_count(page) >= 3);
	lock_page(page);	/* try_to_free_buffers requires this */
	if (page_has_buffers(page)) {
		int ret = try_to_free_buffers(page);
		assert(ret);
	}
	unlock_page(page);
	page->mapping = NULL;
	page_cache_release(page);
	/* Drop the final reference */
	page_cache_release(page);
}
#endif
