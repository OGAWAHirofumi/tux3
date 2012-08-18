#ifndef LIBKLIB_MM_H
#define LIBKLIB_MM_H

/* depending on tux3 */

/*
 * gfp stuff
 */

#define GFP_KERNEL	(__force gfp_t)0x10u
#define GFP_NOFS	(__force gfp_t)0x20u

struct page {
	void *address;
	unsigned long private;
};

#define PAGE_SIZE	(1 << 6)
#define PAGE_CACHE_SIZE	PAGE_SIZE

static inline void *page_address(struct page *page)
{
	return page->address;
}

static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned order)
{
	struct page *page = malloc(sizeof(*page));
	void *data = malloc(PAGE_SIZE);
	if (!page || !data)
		goto error;
	*page = (struct page){ .address = data };
	return page;

error:
	if (page)
		free(page);
	if (data)
		free(data);
	return NULL;
}
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

static inline void __free_pages(struct page *page, unsigned order)
{
	free(page_address(page));
	free(page);
}
#define __free_page(page) __free_pages((page), 0)

/*
 * mm stuff
 */

static inline void truncate_inode_pages_range(map_t *map, loff_t lstart, loff_t lend)
{
	truncate_buffers_range(map, lstart, lend);
}

static inline void truncate_inode_pages(map_t *map, loff_t lstart)
{
	truncate_buffers_range(map, lstart, LLONG_MAX);
}

void truncate_setsize(struct inode *inode, loff_t newsize);

#endif /* !LIBKLIB_MM_H */
