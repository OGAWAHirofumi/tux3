#ifndef _MMAP_HACK_H
#define _MMAP_HACK_H

#ifdef CONFIG_TUX3_MMAP
int page_cow_file(struct page *oldpage, struct page *newpage);
#else
static inline int page_cow_file(struct page *oldpage, struct page *newpage)
{
	return 0;
}
#endif

#endif /* !_MMAP_HACK_H */
