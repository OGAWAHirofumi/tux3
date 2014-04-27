#ifndef _MMAP_HACK_H
#define _MMAP_HACK_H

/*
 * FIXME: copied from mm/internal.h. We should move some functions to
 * mm/, then share codes.
 */
static inline void mlock_migrate_page(struct page *newpage, struct page *page)
{
	if (TestClearPageMlocked(page)) {
		unsigned long flags;
		int nr_pages = hpage_nr_pages(page);

		local_irq_save(flags);
		__mod_zone_page_state(page_zone(page), NR_MLOCK, -nr_pages);
		SetPageMlocked(newpage);
		__mod_zone_page_state(page_zone(newpage), NR_MLOCK, nr_pages);
		local_irq_restore(flags);
#if 0
		/*
		 * FIXME: maybe, we should remove page from LRU, then
		 * putback to LRU. With it, Unevictable will be removed.
		 *
		 * if (!isolate_lru_page(page))
		 *     putback_lru_page(page);
		 */
		BUG_ON(PageUnevictable(page));
#endif
	}
}

#ifdef CONFIG_TUX3_MMAP
int page_cow_file(struct page *oldpage, struct page *newpage);
#else
static inline int page_cow_file(struct page *oldpage, struct page *newpage)
{
	return 0;
}
#endif

#endif /* !_MMAP_HACK_H */
