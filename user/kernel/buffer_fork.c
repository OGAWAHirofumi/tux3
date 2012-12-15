/*
 * Block Fork (Copy-On-Write of logically addressed block)
 */

#include <linux/hugetlb.h>	/* for PageHuge() */
#include <linux/swap.h>		/* for __lru_cache_add() */
#include <linux/cleancache.h>

/*
 * Scanning the freeable forked page.
 *
 * Although we would like to free forked page at early stage (e.g. in
 * blockdirty()). To free page, we have to set NULL to page->mapping,
 * and free buffers on the page. But reader side can be grabbing the
 * forked page, and may use ->mapping or buffers.  So, we have to
 * keep forked page as is until it can be freed.
 *
 * So, we check the forked pages periodically. And if all referencer
 * are gone (checking page_count()), free forked buffer and page.
 */

#define buffer_link(x)		((struct link *)&(x)->b_end_io)
#define buffer_link_entry(x)	__link_entry(x, struct buffer_head, b_end_io)

/*
 * Register forked buffer to free the page later.
 * FIXME: we should replace the hack link by ->b_end_io with something
 */
static void forked_buffer_add(struct sb *sb, struct buffer_head *buffer)
{
	/* Pin buffer. This prevents try_to_free_buffers(). */
	get_bh(buffer);

	spin_lock(&sb->forked_buffers_lock);
	link_add(buffer_link(buffer), &sb->forked_buffers);
	spin_unlock(&sb->forked_buffers_lock);
}

static void forked_buffer_del(struct link *prev, struct buffer_head *buffer)
{
	link_del_next(prev);
	/* Unpin buffer */
	put_bh(buffer);
}

/* Cleaning and free forked page */
static void free_forked_page(struct page *page)
{
	struct address_space *mapping = page->mapping;

	assert(PageForked(page));

	lock_page(page);
	if (page_has_buffers(page)) {
		int ret = try_to_free_buffers(page);
		assert(ret);
	}
	/* Lock is to make sure end_page_writeback() was done completely */
	spin_lock_irq(&mapping->tree_lock);
	page->mapping = NULL;
	spin_unlock_irq(&mapping->tree_lock);
	unlock_page(page);

	/* Drop the radix-tree reference */
	page_cache_release(page);
	/* Drop the final reference */
	trace_on("page %p, count %u", page, page_count(page));
	page_cache_release(page);
}

/* Use same bit with bufdelta though, this buffer never be dirty */
#define buffer_freeable(x)	test_bit(BH_PrivateStart, &(x)->b_state)
#define set_buffer_freeable(x)	set_bit(BH_PrivateStart, &(x)->b_state)
#define clear_buffer_freeable(x) clear_bit(BH_PrivateStart, &(x)->b_state)

static inline int buffer_busy(struct buffer_head *buffer, int refcount)
{
	assert(!buffer_dirty(buffer));
	assert(!buffer_async_write(buffer));
	assert(!buffer_async_read(buffer));

	return atomic_read(&buffer->b_count) > refcount ||
		buffer_locked(buffer);
}

/* There is no referencer? */
static int is_freeable_forked(struct buffer_head *buffer, struct page *page)
{
	/*
	 * There is no reference of buffers? Once reader released
	 * buffer, it never grab again. So we don't need recheck it.
	 */
	if (!buffer_freeable(buffer)) {
		struct buffer_head *tmp = buffer->b_this_page;
		while (tmp != buffer) {
			if (buffer_busy(tmp, 0))
				return 0;
			tmp = tmp->b_this_page;
		}
		/* we have the refcount of this buffer to pin */
		if (buffer_busy(buffer, 1))
			return 0;

		set_buffer_freeable(buffer);
	}

	/* Page is freeable? (radix-tree + ->private + own) */
	return page_count(page) == 3;
}

/*
 * Try to free forked page. If it is called from umount, there should
 * be no referencer. So we free forked page forcefully.
 */
void free_forked_buffers(struct sb *sb, int umount)
{
	struct link free_list, *node, *prev, *n;

	init_link_circular(&free_list);

	/* Move freeable forked page to free_list */
	spin_lock(&sb->forked_buffers_lock);
	link_for_each_safe(node, prev, n, &sb->forked_buffers) {
		struct buffer_head *buffer = buffer_link_entry(node);
		struct page *page = buffer->b_page;

		trace_on("buffer %p, page %p, count %u",
			 buffer, page, page_count(page));
		assert(!PageDirty(page)); /* page should already be submitted */
		assert(!umount || !PageWriteback(page));
		/* I/O was done? */
		if (!PageWriteback(page)) {
			/* All users were gone or from umount? */
			if (umount || is_freeable_forked(buffer, page)) {
				clear_buffer_freeable(buffer);

				link_del_next(prev);
				link_add(buffer_link(buffer), &free_list);
			}
		}
	}
	spin_unlock(&sb->forked_buffers_lock);

	/* Free forked pages */
	while (!link_empty(&free_list)) {
		struct buffer_head *buffer = buffer_link_entry(free_list.next);
		struct page *page = buffer->b_page;

		forked_buffer_del(&free_list, buffer);
		free_forked_page(page);
	}
}

/*
 * Block fork core
 */

/*
 * This replaces the oldpage on radix-tree with newpage atomically.
 *
 * Similar to migrate_pages(), but the oldpage is for writeout.
 * FIXME: we would have to add mmap handling (e.g. replace PTE)
 */
static int tux3_replace_page_cache(struct page *oldpage, struct page *newpage)
{
	struct address_space *mapping = oldpage->mapping;
	void **pslot;

	/* Get refcount for radix-tree */
	page_cache_get(newpage);

	/* Replace page in radix tree. */
	spin_lock_irq(&mapping->tree_lock);
	/* PAGECACHE_TAG_DIRTY represents the view of frontend. Clear it. */
	if (PageDirty(oldpage))
		radix_tree_tag_clear(&mapping->page_tree, page_index(oldpage),
				     PAGECACHE_TAG_DIRTY);
	/* The refcount to newpage is used for radix tree. */
	pslot = radix_tree_lookup_slot(&mapping->page_tree, oldpage->index);
	radix_tree_replace_slot(pslot, newpage);
	__inc_zone_page_state(newpage, NR_FILE_PAGES);
	__dec_zone_page_state(oldpage, NR_FILE_PAGES);
	spin_unlock_irq(&mapping->tree_lock);

#if 0 /* FIXME */
	/* mem_cgroup codes must not be called under tree_lock */
	mem_cgroup_replace_page_cache(oldpage, newpage);
#endif
	/* Release refcount for radix-tree */
	page_cache_release(oldpage);

	return 0;
}

/*
 * This delete the page from radix-tree. But leave page->mapping as is.
 *
 * Similar to truncate_inode_page(), but the oldpage is for writeout.
 * FIXME: we would have to add mmap handling (e.g. replace PTE)
 */
static void tux3_delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	/* Delete page from radix tree. */
	spin_lock_irq(&mapping->tree_lock);
	/*
	 * if we're uptodate, flush out into the cleancache, otherwise
	 * invalidate any existing cleancache entries.  We can't leave
	 * stale data around in the cleancache once our page is gone
	 */
	if (PageUptodate(page) && PageMappedToDisk(page))
		cleancache_put_page(page);
	else
		cleancache_invalidate_page(mapping, page);

	radix_tree_delete(&mapping->page_tree, page->index);
#if 0 /* FIXME: backend is assuming page->mapping is available */
	page->mapping = NULL;
#endif
	/* Leave page->index set: truncation lookup relies upon it */
	mapping->nrpages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);

	/* Dirty accounting is done by writeback path */
	spin_unlock_irq(&mapping->tree_lock);

#if 0 /* FIXME */
	mem_cgroup_uncharge_cache_page(page);
#endif
	page_cache_release(page);
}

/*
 * Clone buffers. But cloned buffer represents the buffer state after
 * flushing buffer.
 */
static void clone_buffers(struct page *oldpage, struct page *newpage)
{
	struct sb *sb = tux_sb(oldpage->mapping->host->i_sb);
	struct buffer_head *head, *newbuf, *oldbuf;
#if 1	/* For now, writeback doesn't use BH_Lock */
#define USE_FOR_IO					\
	((1UL << BH_Uptodate_Lock) | (1UL << BH_Async_Write))
#else
#define USE_FOR_IO					\
	((1UL << BH_Lock) | (1UL << BH_Uptodate_Lock) | (1UL << BH_Async_Write))
#endif

	oldbuf = page_buffers(oldpage);
	newbuf = page_buffers(newpage);
	head = newbuf;
	do {
		assert(!buffer_locked(oldbuf));
		assert(!buffer_async_read(oldbuf));

		newbuf->b_state = oldbuf->b_state;
		/* Adjust ->b_state to after I/O */
		newbuf->b_state &= ~USE_FOR_IO;
		if (buffer_dirty(newbuf))
			tux3_clear_buffer_dirty_for_io(newbuf, sb, 0);

		oldbuf = oldbuf->b_this_page;
		newbuf = newbuf->b_this_page;
	} while (newbuf != head);
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
	clone_buffers(oldpage, newpage);

	return newpage;
}

/* Try to remove from LRU list */
static void oldpage_try_remove_from_lru(struct page *page)
{
	/* Required functions are not exported at 3.4.4 */
}

/* Schedule to add LRU list */
static void newpage_add_lru(struct page *page)
{
	if (TestClearPageActive(page))
		__lru_cache_add(page, LRU_ACTIVE_FILE);
	else
		__lru_cache_add(page, LRU_INACTIVE_FILE);
}

enum ret_needfork {
	RET_FORKED = 1,		/* Someone already forked */
	RET_NEED_FORK,		/* Need to fork to dirty */
	RET_CAN_DIRTY,		/* Can dirty without fork */
	RET_ALREADY_DIRTY,	/* Buffer is already dirtied for delta */
};

static enum ret_needfork
need_fork(struct page *page, struct buffer_head *buffer, unsigned delta)
{
	struct buffer_head *tmp;
	int bufdelta;

	/* Someone already forked this page. */
	if (PageForked(page))
		return RET_FORKED;
	/* Page is under I/O, needs buffer fork */
	if (PageWriteback(page))
		return RET_NEED_FORK;
	/*
	 * If page isn't dirty (and isn't writeback), this is clean
	 * page (and all buffers should be clean on this page).  So we
	 * can just dirty the buffer for current delta.
	 */
	if (!PageDirty(page)) {
		assert(!buffer || !buffer_dirty(buffer));
		return RET_CAN_DIRTY;
	}
	if (buffer == NULL) {
		/* If the page is dirty, it should have buffers */
		assert(page_has_buffers(page));
		buffer = page_buffers(page);
	}

	/*
	 * (Re-)check the buffer and page under lock_page. (We don't
	 * allow the buffer has different delta states on same page.)
	 */
	bufdelta = buffer_check_dirty_delta(buffer->b_state);
	if (bufdelta >= 0) {
		/* Buffer is dirtied by delta, just modify this buffer */
		if (bufdelta == tux3_delta(delta))
			return RET_ALREADY_DIRTY;

		/* Buffer was dirtied by different delta, we need buffer fork */
		return RET_NEED_FORK;
	}

	/*
	 * Check other buffers sharing same page.
	 */
	tmp = buffer->b_this_page;
	while (tmp != buffer) {
		if (!buffer_can_modify(tmp, delta)) {
			/* The buffer can't be modified for delta */
			return RET_NEED_FORK;
		}

		tmp = tmp->b_this_page;
	}

	/* This page can be modified, dirty this buffer */
	return RET_CAN_DIRTY;
}

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
	struct page *newpage, *oldpage = buffer->b_page;
	struct sb *sb;
	struct buffer_head *newbuf;
	enum ret_needfork ret_needfork;
	int err;

	trace("buffer %p, page %p, index %lx, count %u",
	      buffer, oldpage, oldpage->index, page_count(oldpage));
	trace("forked %u, dirty %u, writeback %u",
	      PageForked(oldpage), PageDirty(oldpage), PageWriteback(oldpage));

	/* The simple case: redirty on same delta */
	if (buffer_already_dirty(buffer, newdelta))
		return buffer;

	/* Take page lock to protect buffer list, and concurrent block_fork */
	lock_page(oldpage);

	/* This happens on partially dirty page. */
//	assert(PageUptodate(page));

	switch ((ret_needfork = need_fork(oldpage, buffer, newdelta))) {
	case RET_FORKED:
		/* This page was already forked. Retry from lookup page. */
		buffer = ERR_PTR(-EAGAIN);
		WARN_ON(1);
		/* FALLTHRU */
	case RET_ALREADY_DIRTY:
		/* This buffer was already dirtied. Done. */
		goto out;
	case RET_CAN_DIRTY:
	case RET_NEED_FORK:
		break;
	default:
		BUG();
		break;
	}

	/* Checked buffer and oldpage, now oldpage->mapping should be valid. */
	sb = tux_sb(oldpage->mapping->host->i_sb);

	if (ret_needfork == RET_CAN_DIRTY) {
		/* We can dirty this buffer. */
		goto dirty_buffer;
	}

	/*
	 * We need to buffer fork. Start to clone the oldpage.
	 */
	newpage = clone_page(oldpage, sb->blocksize);
	if (IS_ERR(newpage)) {
		buffer = ERR_CAST(newpage);
		goto out;
	}

	newbuf = __get_buffer(newpage, bh_offset(buffer) >> sb->blockbits);
	/* Grab buffer to pin page, then release refcount of page */
	get_bh(newbuf);
	page_cache_release(newpage);

	/* We keep page->mapping as is, so get refcount for radix-tree. */
	page_cache_get(oldpage);

	/* Replace oldpage on radix-tree with newpage */
	err = tux3_replace_page_cache(oldpage, newpage);

	newpage_add_lru(newpage);

	/*
	 * Referencer are dummy radix-tree + ->private (plus other
	 * users and lru_cache).
	 *
	 * FIXME: We can't remove from LRU, because page can be on
	 * per-cpu lru cache at here. So, vmscan will try to free
	 * oldpage. We get refcount to pin oldpage to prevent vmscan
	 * try to release oldpage.
	 */
	trace("oldpage count %u", page_count(oldpage));
	assert(page_count(oldpage) >= 2);
	page_cache_get(oldpage);
	oldpage_try_remove_from_lru(oldpage);

	/*
	 * This prevents to re-fork the oldpage. And we guarantee the
	 * newpage is available on radix-tree here.
	 */
	SetPageForked(oldpage);
	unlock_page(oldpage);

	/* Register forked buffer to free forked page later */
	forked_buffer_add(sb, buffer);
	brelse(buffer);

	trace("cloned page %p, buffer %p", newpage, newbuf);
	buffer = newbuf;
	oldpage = newpage;

dirty_buffer:
	assert(!buffer_dirty(buffer));
	__tux3_mark_buffer_dirty(buffer, newdelta);

out:
	unlock_page(oldpage);

	return buffer;
}

/*
 * Do buffer fork for oldpage if needed. Then return page with locked.
 * Page is locked, so, the caller can call __tux3_mark_buffer_dirty()
 * (without checking buffer fork) to dirty buffers on the returned page,
 * until unlock page.
 *
 * Caller must hold refcount of oldpage and hold lock_page(oldpage)
 */
struct page *pagefork_for_blockdirty(struct page *oldpage, unsigned newdelta)
{
	struct page *newpage = oldpage;
	struct sb *sb;
	enum ret_needfork ret_needfork;
	int err;

	/* Check page lock to protect buffer list, and concurrent block_fork */
	assert(PageLocked(oldpage));

	trace("page %p, index %lx, count %u",
	      oldpage, oldpage->index, page_count(oldpage));
	trace("forked %u, dirty %u, writeback %u",
	      PageForked(oldpage), PageDirty(oldpage), PageWriteback(oldpage));

	/* This happens on partially dirty page. */
//	assert(PageUptodate(page));

	switch ((ret_needfork = need_fork(oldpage, NULL, newdelta))) {
	case RET_FORKED:
		/* This page was already forked. Retry from lookup page. */
		newpage = ERR_PTR(-EAGAIN);
		WARN_ON(1);
	case RET_ALREADY_DIRTY:
		/* This buffer was already dirtied. Done. */
		goto out;
	case RET_CAN_DIRTY:
	case RET_NEED_FORK:
		break;
	default:
		BUG();
		break;
	}

	/* Checked buffer and oldpage, now oldpage->mapping should be valid. */
	sb = tux_sb(oldpage->mapping->host->i_sb);

	if (ret_needfork == RET_CAN_DIRTY) {
		/* We can dirty this buffer. */
		goto out;
	}

	/*
	 * We need to buffer fork. Start to clone the oldpage.
	 */
	newpage = clone_page(oldpage, sb->blocksize);
	if (IS_ERR(newpage))
		goto out;

	/*
	 * We keep page->mapping as is, so inherit refcount of caller
	 * for radix-tree.
	 */
	/*page_cache_get(oldpage);*/

	/* Replace oldpage on radix-tree with newpage */
	err = tux3_replace_page_cache(oldpage, newpage);

	newpage_add_lru(newpage);

	/*
	 * Referencer are dummy radix-tree + ->private (plus other
	 * users and lru_cache).
	 *
	 * FIXME: We can't remove from LRU, because page can be on
	 * per-cpu lru cache at here. So, vmscan will try to free
	 * oldpage. We get refcount to pin oldpage to prevent vmscan
	 * try to release oldpage.
	 */
	trace("oldpage count %u", page_count(oldpage));
	assert(page_count(oldpage) >= 2);
	page_cache_get(oldpage);
	oldpage_try_remove_from_lru(oldpage);

	/*
	 * This prevents to re-fork the oldpage. And we guarantee the
	 * newpage is available on radix-tree here.
	 */
	SetPageForked(oldpage);
	unlock_page(oldpage);

	/* Register forked buffer to free forked page later */
	forked_buffer_add(sb, page_buffers(oldpage));

	trace("cloned page %p", newpage);

out:
	return newpage;
}

/*
 * This checks the page whether we can invalidate. If the page is
 * stabled, we can't invalidate the buffers on page. So, this forks
 * the page without making clone page.
 *
 * 1 - fork was done to invalidate (i.e. page was removed from radix-tree)
 * 0 - fork was not done (i.e. buffers on page can be invalidated)
 */
int bufferfork_to_invalidate(struct address_space *mapping, struct page *page)
{
	struct sb *sb = tux_sb(mapping->host->i_sb);
	unsigned delta = tux3_inode_delta(mapping->host);

	assert(PageLocked(page));

	switch (need_fork(page, NULL, delta)) {
	case RET_NEED_FORK:
		/* Need to fork, then delete from radix-tree */
		break;
	case RET_ALREADY_DIRTY:
	case RET_CAN_DIRTY:
		/* We can invalidate the page */
		return 0;
	case RET_FORKED:
		trace_on("mapping %p, page %p", mapping, page);
		/* FALLTHRU */
	default:
		BUG();
		break;
	}

	/* We keep page->mapping as is, so get refcount for radix-tree. */
	page_cache_get(page);

	/* Delete page from radix-tree */
	tux3_delete_from_page_cache(page);

	/*
	 * Referencer are dummy radix-tree + ->private (plus other
	 * users and lru_cache).
	 *
	 * FIXME: We can't remove from LRU, because page can be on
	 * per-cpu lru cache at here. So, vmscan will try to free
	 * page. We get refcount to pin page to prevent vmscan
	 * try to release page.
	 */
	trace("page count %u", page_count(page));
	assert(page_count(page) >= 2);
	page_cache_get(page);
	oldpage_try_remove_from_lru(page);

	/*
	 * This prevents to re-fork the page. And we guarantee the
	 * newpage is available on radix-tree here.
	 */
	SetPageForked(page);

	/* Register forked buffer to free forked page later */
	forked_buffer_add(sb, page_buffers(page));

	return 1;
}
