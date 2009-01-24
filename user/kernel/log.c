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
	if (sb->logpos + bytes > sb->logtop) {
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

void log_alloc(struct sb *sb, block_t block, unsigned count, unsigned alloc)
{
	unsigned char *data = log_begin(sb, 8);
	*data++ = alloc ? LOG_ALLOC : LOG_FREE;
	*data++ = count;
	log_end(sb, encode48(data, block));
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
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	data = encode48(data, oldroot);
	log_end(sb, encode48(data, key));
}

void log_iroot(struct sb *sb, block_t newroot, block_t oldroot)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	log_end(sb, encode48(data, oldroot));
}

void log_redirect(struct sb *sb, block_t newblock, block_t oldblock)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_REDIRECT;
	data = encode48(data, newblock);
	log_end(sb, encode48(data, oldblock));
}

/* Deferred free list */

int stash_value(struct stash *stash, u64 value)
{
	if (stash->pos == stash->top) {
		struct page *page = alloc_page(GFP_KERNEL);
		if (!page)
			return -ENOMEM;
		stash->top = page_address(page) + PAGE_SIZE;
		stash->pos = page_address(page);
		if (stash->tail) {
			link_add(page_link(page), stash->tail);
			stash->tail = stash->tail->next;
		} else {
			stash->tail = page_link(page);
			stash->tail->next = stash->tail;
		}
	}
	*stash->pos++ = value;
	return 0;
}

void empty_stash(struct stash *stash)
{
	struct link *tail = stash->tail;
	if (!tail)
		return;
	do {
		struct page *page = link_entry(tail, struct page, private);
		tail = tail->next;
		__free_page(page);
	} while (tail != stash->tail);
	stash->tail = NULL;
}

int stash_free(struct stash *stash, block_t block, unsigned count)
{
	return stash_value(stash, ((u64)count << 48) + block);
}

int retire_frees(struct sb *sb, struct stash *stash)
{
	while (1) {
		int err;
		struct page *page = link_entry(stash->tail->next, struct page, private);
		u64 *vec = page_address(page), *top = page_address(page) + PAGE_SIZE;
		if (top == stash->top)
			top = stash->pos;
		for (; vec < top; vec++)
			if ((err = bfree(sb, *vec & ~(-1ULL << 48), *vec >> 48)))
				return err;
		if (stash->tail == stash->tail->next)
			break;
		link_del_next(stash->tail);
		__free_page(page);
	}
	stash->pos = stash->top - PAGE_SIZE;
	return 0;
}
