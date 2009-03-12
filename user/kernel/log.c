/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

void log_next(struct sb *sb)
{
	sb->logbuf = blockget(mapping(sb->logmap), sb->lognext++);
	sb->logpos = bufdata(sb->logbuf) + sizeof(struct logblock);
	sb->logtop = bufdata(sb->logbuf) + sb->blocksize;
}

void log_finish(struct sb *sb)
{
	struct logblock *log = bufdata(sb->logbuf);
	assert(sb->logtop >= sb->logpos);
	log->bytes = to_be_u16(sb->logpos - log->data);
	memset(sb->logpos, 0, sb->logtop - sb->logpos);
	brelse(sb->logbuf);
	sb->logbuf = NULL;
}

void *log_begin(struct sb *sb, unsigned bytes)
{
	mutex_lock(&sb->loglock);
	if (1 || sb->logpos + bytes > sb->logtop) {
		if (sb->logbuf)
			log_finish(sb);
		log_next(sb);
		*(struct logblock *)bufdata(sb->logbuf) = (struct logblock){
			.magic = to_be_u16(0xc0de) };
	}
	return sb->logpos;
}

void log_end(struct sb *sb, void *pos)
{
	sb->logpos = pos;
	mutex_unlock(&sb->loglock);
}

static void log_extent(struct sb *sb, u8 intent, block_t block, unsigned count)
{
	unsigned char *data = log_begin(sb, 8);

	*data++ = intent;
	*data++ = count;
	log_end(sb, encode48(data, block));
}

void log_balloc(struct sb *sb, block_t block, unsigned count)
{
	log_extent(sb, LOG_ALLOC, block, count);
}

void log_bfree(struct sb *sb, block_t block, unsigned count)
{
	log_extent(sb, LOG_FREE, block, count);
}

void log_update(struct sb *sb, block_t child, block_t parent, tuxkey_t key)
{
	unsigned char *data = log_begin(sb, 19);

	*data++ = LOG_UPDATE;
	data = encode48(data, child);
	data = encode48(data, parent);
	log_end(sb, encode48(data, key));
}

void log_droot(struct sb *sb, block_t newroot, block_t oldroot, tuxkey_t key)
{
return;
	unsigned char *data = log_begin(sb, 19);

	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	data = encode48(data, oldroot);
	log_end(sb, encode48(data, key));
}

void log_iroot(struct sb *sb, block_t newroot, block_t oldroot)
{
return;
	unsigned char *data = log_begin(sb, 19);

	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	log_end(sb, encode48(data, oldroot));
}

void log_redirect(struct sb *sb, block_t newblock, block_t oldblock)
{
return;
	unsigned char *data = log_begin(sb, 19);

	*data++ = LOG_REDIRECT;
	data = encode48(data, newblock);
	log_end(sb, encode48(data, oldblock));
}

/* Stash infrastructure (struct stash must be initialized by zero clear) */

static inline struct link *page_link(struct page *page)
{
	return (void *)&page->private;
}

static void stash_init(struct stash *stash)
{
	init_flink_head(&stash->head);
	stash->pos = stash->top = NULL;
}

int stash_value(struct stash *stash, u64 value)
{
	if (stash->pos == stash->top) {
		struct page *page = alloc_page(GFP_NOFS);
		if (!page)
			return -ENOMEM;
		stash->top = page_address(page) + PAGE_SIZE;
		stash->pos = page_address(page);
		if (!flink_empty(&stash->head))
			flink_add(page_link(page), &stash->head);
		else
			flink_first_add(page_link(page), &stash->head);
	}
	*stash->pos++ = value;
	return 0;
}

void empty_stash(struct stash *stash)
{
	struct flink_head *head = &stash->head;

	if (!flink_empty(head)) {
		struct page *page;
		while (1) {
			page = flink_next_entry(head, struct page, private);
			if (flink_is_last(head))
				break;
			flink_del_next(head);
			__free_page(page);
		}
		__free_page(page);
		stash_init(stash);
	}
}

/* Deferred free list */

int defer_free(struct stash *defree, block_t block, unsigned count)
{
	return stash_value(defree, ((u64)count << 48) + block);
}

int unstash(struct sb *sb, struct stash *defree, unstash_t actor)
{
	struct flink_head *head = &defree->head;
	struct page *page;

	if (flink_empty(head))
		return 0;
	while (1) {
		int err;
		page = flink_next_entry(head, struct page, private);
		u64 *vec = page_address(page), *top = page_address(page) + PAGE_SIZE;
		if (top == defree->top)
			top = defree->pos;
		for (; vec < top; vec++)
			if ((err = actor(sb, *vec)))
				return err;
		if (flink_is_last(head))
			break;
		flink_del_next(head);
		__free_page(page);
	}
	defree->pos = page_address(page);
	return 0;
}

void destroy_defree(struct stash *defree)
{
	empty_stash(defree);
}
