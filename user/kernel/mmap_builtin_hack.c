/*
 * mmap support helpers. But core doesn't provide functionality that
 * pagefork needs.
 *
 * So, this hack adds EXPORT_SYMBOL_GPL() and inline functions, and
 * liked with kernel statically.
 *
 * FIXME: we should patch the kernel instead.
 */

#include "tux3.h"
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>

extern unsigned long vma_address(struct page *page, struct vm_area_struct *vma);

static int page_cow_one(struct page *oldpage, struct page *newpage,
			struct vm_area_struct *vma, unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t oldptval, ptval, *pte;
	spinlock_t *ptl;
	int ret = 0;

	pte = page_check_address(oldpage, mm, address, &ptl, 1);
	if (!pte)
		goto out;

	flush_cache_page(vma, address, pte_pfn(*pte));
	oldptval = ptep_clear_flush(vma, address, pte);

	/* Take refcount for PTE */
	page_cache_get(newpage);

	/*
	 * vm_page_prot doesn't have writable bit, so page fault will
	 * be occurred immediately after returned from this page fault
	 * again. And second time of page fault will be resolved with
	 * forked page was set here.
	 *
	 * FIXME: we should resolve page fault with one page
	 * fault. Maybe, we will have to modify callers of
	 * ->page_mkwrite().
	 */
	ptval = mk_pte(newpage, vma->vm_page_prot);
#if 0
	if (pte_dirty(oldptval))
		ptval = pte_mkdirty(ptval);
	if (pte_young(oldptval))
		ptval = pte_mkyoung(ptval);
#endif
	set_pte_at(mm, address, pte, ptval);

	/* Update rmap accounting */
	assert(!PageMlocked(oldpage));	/* Caller should migrate mlock flag */
	page_remove_rmap(oldpage);
	page_add_file_rmap(newpage);

	/* no need to invalidate: a not-present page won't be cached */
	update_mmu_cache(vma, address, pte);

	pte_unmap_unlock(pte, ptl);

	mmu_notifier_invalidate_page(mm, address);

	/* Release refcount for PTE */
	page_cache_release(oldpage);
out:
	return ret;
}

int page_cow_file(struct page *oldpage, struct page *newpage)
{
	struct address_space *mapping = page_mapping(oldpage);
	pgoff_t pgoff = oldpage->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	int ret = 0;

	BUG_ON(!PageLocked(oldpage));
	BUG_ON(!PageLocked(newpage));
	BUG_ON(PageAnon(oldpage));
	BUG_ON(mapping == NULL);

	mutex_lock(&mapping->i_mmap_mutex);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if (vma->vm_flags & VM_SHARED) {
			unsigned long address = vma_address(oldpage, vma);
			ret += page_cow_one(oldpage, newpage, vma, address);
		}
	}
	mutex_unlock(&mapping->i_mmap_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(page_cow_file);
