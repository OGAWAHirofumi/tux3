/*
 * mmap(2) handlers to support page fork.
 */

/*
 * Copy of __set_page_dirty() without __mark_inode_dirty(). Caller
 * decides whether mark inode dirty or not.
 */
void __tux3_set_page_dirty_account(struct page *page,
				   struct address_space *mapping, int warn)
{
	unsigned long flags;

	spin_lock_irqsave(&mapping->tree_lock, flags);
	if (page->mapping) {	/* Race with truncate? */
		WARN_ON_ONCE(warn && !PageUptodate(page));
		account_page_dirtied(page, mapping);
		radix_tree_tag_set(&mapping->page_tree,
				page_index(page), PAGECACHE_TAG_DIRTY);
	}
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
}

static void __tux3_set_page_dirty(struct page *page,
				  struct address_space *mapping, int warn)
{
	__tux3_set_page_dirty_account(page, mapping, warn);
	__tux3_mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
}

static int tux3_set_page_dirty_buffers(struct page *page)
{
#if 0
	struct address_space *mapping = page->mapping;
	int newly_dirty;

	spin_lock(&mapping->private_lock);
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		do {
			set_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	newly_dirty = !TestSetPageDirty(page);
	spin_unlock(&mapping->private_lock);

	if (newly_dirty)
		__set_page_dirty(page, mapping, 1);

	return newly_dirty;
#else
	struct address_space *mapping = page->mapping;
	unsigned delta = tux3_get_current_delta();
	struct buffer_head *head, *buffer;
	int newly_dirty;

	/* This should be tux3 page and locked */
	assert(mapping);
	assert(PageLocked(page));
	/* This page should have buffers (caller should allocate) */
	assert(page_has_buffers(page));

	/*
	 * FIXME: we dirty all buffers on this page, so we optimize this
	 * by avoiding to check page-dirty/inode-dirty multiple times.
	 */
	newly_dirty = 0;
	if (!TestSetPageDirty(page)) {
		__tux3_set_page_dirty(page, mapping, 1);
		newly_dirty = 1;
	}
	buffer = head = page_buffers(page);
	do {
		__tux3_mark_buffer_dirty(buffer, delta);
		buffer = buffer->b_this_page;
	} while (buffer != head);
#endif
	return newly_dirty;
}

/* Copy of set_page_dirty() */
static int tux3_set_page_dirty(struct page *page)
{
	/*
	 * readahead/lru_deactivate_page could remain
	 * PG_readahead/PG_reclaim due to race with end_page_writeback
	 * About readahead, if the page is written, the flags would be
	 * reset. So no problem.
	 * About lru_deactivate_page, if the page is redirty, the flag
	 * will be reset. So no problem. but if the page is used by readahead
	 * it will confuse readahead and make it restart the size rampup
	 * process. But it's a trivial problem.
	 */
	ClearPageReclaim(page);

	return tux3_set_page_dirty_buffers(page);
}

static int tux3_set_page_dirty_assert(struct page *page)
{
	struct buffer_head *head, *buffer;

	/* See comment of tux3_set_page_dirty() */
	ClearPageReclaim(page);

	/* Is there any cases to be called for old page of forked page? */
	WARN_ON(PageForked(page));

	/* This page should be dirty already, otherwise we will lost data. */
	assert(PageDirty(page));
	/* All buffers should be dirty already, otherwise we will lost data. */
	assert(page_has_buffers(page));
	head = buffer = page_buffers(page);
	do {
		assert(buffer_dirty(buffer));
		buffer = buffer->b_this_page;
	} while (buffer != head);

	return 0;
}

static int tux3_set_page_dirty_bug(struct page *page)
{
	/* See comment of tux3_set_page_dirty() */
	ClearPageReclaim(page);

	assert(0);
	/* This page should not be mmapped */
	assert(!page_mapped(page));
	/* This page should be dirty already, otherwise we will lost data. */
	assert(PageDirty(page));
	return 0;
}

static int tux3_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct sb *sb = tux_sb(inode->i_sb);
	struct page *clone, *page = vmf->page;
	void *ptr;
	int ret;

	sb_start_pagefault(inode->i_sb);

retry:
	down_read(&tux_inode(inode)->truncate_lock);
	lock_page(page);
	if (page->mapping != mapping(inode)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	/*
	 * page fault can be happened while holding change_begin/end()
	 * (e.g. copy of user data between ->write_begin and
	 * ->write_end for write(2)).
	 *
	 * So, we use nested version here.
	 */
	change_begin_atomic_nested(sb, &ptr);

	/*
	 * FIXME: Caller releases vmf->page (old_page) unconditionally.
	 * So, this takes additional refcount to workaround it.
	 */
	if (vmf->page == page)
		page_cache_get(page);

	clone = pagefork_for_blockdirty(page, tux3_get_current_delta());
	if (IS_ERR(clone)) {
		/* Someone did page fork */
		pgoff_t index = page->index;

		change_end_atomic_nested(sb, ptr);
		unlock_page(page);
		page_cache_release(page);
		up_read(&tux_inode(inode)->truncate_lock);

		switch (PTR_ERR(clone)) {
		case -EAGAIN:
			page = find_get_page(inode->i_mapping, index);
			assert(page);
			goto retry;
		case -ENOMEM:
			ret = VM_FAULT_OOM;
			break;
		default:
			ret = VM_FAULT_SIGBUS;
			break;
		}

		goto out;
	}

	file_update_time(vma->vm_file);

	/* Assign buffers to dirty */
	if (!page_has_buffers(clone))
		create_empty_buffers(clone, sb->blocksize, 0);

	/*
	 * We mark the page dirty already here so that when freeze is in
	 * progress, we are guaranteed that writeback during freezing will
	 * see the dirty page and writeprotect it again.
	 */
	tux3_set_page_dirty(clone);
#if 1
	/* FIXME: Caller doesn't see the changed vmf->page */
	vmf->page = clone;

	change_end_atomic_nested(sb, ptr);
	/* FIXME: caller doesn't know about pagefork */
	unlock_page(clone);
	page_cache_release(clone);
	ret = 0;
//	ret = VM_FAULT_LOCKED;
#endif
out:
	up_read(&tux_inode(inode)->truncate_lock);
	sb_end_pagefault(inode->i_sb);

	return ret;
}

static const struct vm_operations_struct tux3_file_vm_ops = {
	.fault		= filemap_fault,
	.page_mkwrite	= tux3_page_mkwrite,
	.remap_pages	= generic_file_remap_pages,
};

int tux3_file_mmap(struct file *file, struct vm_area_struct *vma)
{
#ifdef CONFIG_TUX3_MMAP
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;

	file_accessed(file);
	vma->vm_ops = &tux3_file_vm_ops;

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}
