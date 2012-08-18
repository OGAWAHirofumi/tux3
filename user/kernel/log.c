/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

/*
 * Log cache scheme
 *
 *  - The purpose of the log is to reconstruct pinned metadata that has become
 *    dirty since the last log flush, in case of shutdown without log flush.
 *
 *  - Log blocks are cached in the page cache mapping of an internal inode,
 *    sb->logmap.  The inode itself is not used, just the mapping, so with a
 *    some work we could create/destroy the mapping by itself without the inode.
 *
 *  - Log blocks are indexed logically in sb->logmap, starting from zero at
 *    mount time and incrementing for each new log block and possibly wrapping
 *    back to zero if the filesystem is mounted long enough.
 *
 *  - There is no direct mapping from the log block cache to physical disk,
 *    instead there is a reverse chain starting from sb->logchain.  Log blocks
 *    are read only at replay on mount and written only at delta transition.
 *
 *  - sb->logbase: Logical index of the oldest log block in rollup cycle
 *  - sb->logthis: Logical index of the oldest log block in delta cycle
 *  - sb->lognext: Logmap index of next log block
 *  - sb->logpos/logtop: Pointer/limit to write next log entry
 *  - sb->logbuf: Cached log block referenced by logpos/logtop
 *
 *  - Log blocks older than the last committed delta are not actually needed
 *    in normal operation, just at replay, so sb->logbase might not actually
 *    be needed.
 *
 *  - At delta staging, physical addresses are assigned for log blocks from
 *    logthis to lognext, reverse chain pointers are set in the log blocks, and
 *    all log blocks for the delta are submitted for writeout.
 *
 *  - At delta commit, count of log blocks from logthis to lognext is recorded
 *    in superblock (later, metablock) which are the log blocks for the current
 *    rollup cycle.
 *
 *  - On delta completion, if log was rolluped in current delta then log blocks
 *    are freed for reuse.  Log blocks to be freed are recorded in sb->derollup,
 *    which is appended to sb->defree, the per-delta deferred free list at log
 *    flush time.
 *
 *  - On replay, sb->logcount log blocks for current rollup cycle are loaded in
 *    reverse order into logmap, using the log block reverse chain pointers.
 *
 * Log block format
 *
 *  - Each log block has a header and one or more variable sized entries,
 *    serially encoded.
 *
 *  - Format and handling of log block entries is similar to inode attributes.
 *
 *  - Log block header records size of log block payload in ->bytes.
 *
 *  - Each log block entry has a one byte type code implying its length.
 *
 *  - Integer fields are big endian, byte aligned.
 *
 */

unsigned log_size[] = {
	[LOG_BALLOC]		= 8,
	[LOG_BFREE]		= 8,
	[LOG_BFREE_ON_ROLLUP]	= 8,
	[LOG_BFREE_RELOG]	= 8,
	[LOG_LEAF_REDIRECT]	= 13,
	[LOG_BNODE_REDIRECT]	= 13,
	[LOG_BNODE_ROOT]	= 26,
	[LOG_BNODE_SPLIT]	= 15,
	[LOG_BNODE_ADD]		= 19,
	[LOG_BNODE_UPDATE]	= 19,
	[LOG_BNODE_MERGE]	= 13,
	[LOG_BNODE_DEL]		= 15,
	[LOG_BNODE_ADJUST]	= 19,
	[LOG_FREEBLOCKS]	= 7,
	[LOG_ROLLUP]		= 1,
	[LOG_DELTA]		= 1,
};

void log_next(struct sb *sb)
{
	/* FIXME: error handling of blockget() */
	sb->logbuf = blockget(mapping(sb->logmap), sb->lognext++);
	sb->logpos = bufdata(sb->logbuf) + sizeof(struct logblock);
	sb->logtop = bufdata(sb->logbuf) + sb->blocksize;
}

void log_drop(struct sb *sb)
{
	blockput(sb->logbuf);
	sb->logbuf = NULL;
	sb->logtop = sb->logpos = NULL;
}

void log_finish(struct sb *sb)
{
	if (sb->logbuf) {
		struct logblock *log = bufdata(sb->logbuf);
		assert(sb->logtop >= sb->logpos);
		log->bytes = to_be_u16(sb->logpos - log->data);
		memset(sb->logpos, 0, sb->logtop - sb->logpos);
		log_drop(sb);
	}
}

static void *log_begin(struct sb *sb, unsigned bytes)
{
	mutex_lock(&sb->loglock);
	if (sb->logpos + bytes > sb->logtop) {
		log_finish(sb);
		log_next(sb);
		*(struct logblock *)bufdata(sb->logbuf) = (struct logblock){
			.magic = to_be_u16(TUX3_MAGIC_LOG) };
	}
	return sb->logpos;
}

static void log_end(struct sb *sb, void *pos)
{
	sb->logpos = pos;
	mutex_unlock(&sb->loglock);
}

static void log_intent(struct sb *sb, u8 intent)
{
	/* Check whether array is uptodate */
	BUILD_BUG_ON(ARRAY_SIZE(log_size) != LOG_TYPES);

	unsigned char *data = log_begin(sb, 1);
	*data++ = intent;
	log_end(sb, data);
}

static void log_u48(struct sb *sb, u8 intent, u64 v1)
{
	unsigned char *data = log_begin(sb, log_size[intent]);
	*data++ = intent;
	log_end(sb, encode48(data, v1));
}

static void log_u8_u48(struct sb *sb, u8 intent, u8 v1, u64 v2)
{
	unsigned char *data = log_begin(sb, log_size[intent]);
	*data++ = intent;
	*data++ = v1;
	log_end(sb, encode48(data, v2));
}

static void log_u48_u48(struct sb *sb, u8 intent, u64 v1, u64 v2)
{
	unsigned char *data = log_begin(sb, log_size[intent]);
	*data++ = intent;
	data = encode48(data, v1);
	log_end(sb, encode48(data, v2));
}

static void log_u16_u48_u48(struct sb *sb, u8 intent, u16 v1, u64 v2, u64 v3)
{
	unsigned char *data = log_begin(sb, log_size[intent]);
	*data++ = intent;
	data = encode16(data, v1);
	data = encode48(data, v2);
	log_end(sb, encode48(data, v3));
}

static void log_u48_u48_u48(struct sb *sb, u8 intent, u64 v1, u64 v2, u64 v3)
{
	unsigned char *data = log_begin(sb, log_size[intent]);
	*data++ = intent;
	data = encode48(data, v1);
	data = encode48(data, v2);
	log_end(sb, encode48(data, v3));
}

/* balloc() until next rollup */
void log_balloc(struct sb *sb, block_t block, unsigned count)
{
	assert(count < 256);	/* FIXME: extent max is 64 for now */
	log_u8_u48(sb, LOG_BALLOC, count, block);
}

/* Defered bfree() */
void log_bfree(struct sb *sb, block_t block, unsigned count)
{
	assert(count < 256);	/* FIXME: extent max is 64 for now */
	log_u8_u48(sb, LOG_BFREE, count, block);
}

/* Defered bfree() until after next rollup */
void log_bfree_on_rollup(struct sb *sb, block_t block, unsigned count)
{
	assert(count < 256);	/* FIXME: extent max is 64 for now */
	log_u8_u48(sb, LOG_BFREE_ON_ROLLUP, count, block);
}

/* Same with log_bfree() (re-logged log_bfree_on_rollup() on rollup) */
void log_bfree_relog(struct sb *sb, block_t block, unsigned count)
{
	assert(count < 256);	/* FIXME: extent max is 64 for now */
	log_u8_u48(sb, LOG_BFREE_RELOG, count, block);
}

/*
 * 1. balloc(newblock) until next rollup
 * 2. Defered bfree(oldblock)
 */
void log_leaf_redirect(struct sb *sb, block_t oldblock, block_t newblock)
{
	log_u48_u48(sb, LOG_LEAF_REDIRECT, oldblock, newblock);
}

/*
 * 1. Redirect from oldblock to newblock
 * 2. balloc(newblock) until next rollup
 * 2. Defered bfree(oldblock) until after next rollup
 */
void log_bnode_redirect(struct sb *sb, block_t oldblock, block_t newblock)
{
	log_u48_u48(sb, LOG_BNODE_REDIRECT, oldblock, newblock);
}

/*
 * 1. Construct root buffer until next rollup
 * 2. balloc(root) until next rollup
 */
/* The left key should always be 0 on new root */
void log_bnode_root(struct sb *sb, block_t root, unsigned count,
		    block_t left, block_t right, tuxkey_t rkey)
{
	unsigned char *data = log_begin(sb, log_size[LOG_BNODE_ROOT]);
	assert(count == 1 || count == 2);
	*data++ = LOG_BNODE_ROOT;
	*data++ = count;
	data = encode48(data, root);
	data = encode48(data, left);
	data = encode48(data, right);
	log_end(sb, encode48(data, rkey));
}

/*
 * 1. Split bnode from src to dst until next rollup
 * 2. balloc(dst) until next rollup
 * (src buffer must be dirty already)
 */
void log_bnode_split(struct sb *sb, block_t src, unsigned pos, block_t dst)
{
	log_u16_u48_u48(sb, LOG_BNODE_SPLIT, pos, src, dst);
}

/*
 * Insert new index (child, key) to parent until next rollup
 * (parent buffer must be dirty already)
 */
void log_bnode_add(struct sb *sb, block_t parent, block_t child, tuxkey_t key)
{
	log_u48_u48_u48(sb, LOG_BNODE_ADD, parent, child, key);
}

/*
 * Update ->block of "key" index by child on parent until next rollup
 * (parent buffer must be dirty already)
 */
void log_bnode_update(struct sb *sb, block_t parent, block_t child, tuxkey_t key)
{
	log_u48_u48_u48(sb, LOG_BNODE_UPDATE, parent, child, key);
}

/*
 * 1. Merge btree nodes from src to dst until next rollup
 * 2. Defered bfree(src)
 * (src and dst buffers must be dirty already)
 */
void log_bnode_merge(struct sb *sb, block_t src, block_t dst)
{
	log_u48_u48(sb, LOG_BNODE_MERGE, src, dst);
}

/*
 * Delete indexes specified by (key, count) in bnode until next rollup
 * (bnode buffer must be dirty already)
 */
void log_bnode_del(struct sb *sb, block_t bnode, tuxkey_t key, unsigned count)
{
	log_u16_u48_u48(sb, LOG_BNODE_DEL, count, bnode, key);
}

/*
 * Adjust ->key of index specified by "from" to "to" until next rollup
 * (bnode buffer must be dirty already)
 */
void log_bnode_adjust(struct sb *sb, block_t bnode, tuxkey_t from, tuxkey_t to)
{
	log_u48_u48_u48(sb, LOG_BNODE_ADJUST, bnode, from, to);
}

/* Current freeblocks on rollup */
void log_freeblocks(struct sb *sb, block_t freeblocks)
{
	log_u48(sb, LOG_FREEBLOCKS, freeblocks);
}

/* Log to know where is new rollup cycle  */
void log_rollup(struct sb *sb)
{
	log_intent(sb, LOG_ROLLUP);
}

/* Just add log record as delta mark (for debugging) */
void log_delta(struct sb *sb)
{
	log_intent(sb, LOG_DELTA);
}

/* Stash infrastructure (struct stash must be initialized by zero clear) */

/*
 * Stash utility - store an arbitrary number of u64 values in a linked queue
 * of pages.
 */

static inline struct link *page_link(struct page *page)
{
	return (void *)&page->private;
}

void stash_init(struct stash *stash)
{
	init_flink_head(&stash->head);
	stash->pos = stash->top = NULL;
}

/* Add new entry (value) to stash */
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

/* Free all pages in stash to empty. */
static void empty_stash(struct stash *stash)
{
	struct flink_head *head = &stash->head;

	if (!flink_empty(head)) {
		struct page *page;
		while (1) {
			page = __flink_next_entry(head, struct page, private);
			if (flink_is_last(head))
				break;
			flink_del_next(head);
			__free_page(page);
		}
		__free_page(page);
		stash_init(stash);
	}
}

/*
 * Call actor() for each entries. And, prepare to add new entry to stash.
 * (NOTE: after this, stash keeps one page for future stash_value().)
 */
int unstash(struct sb *sb, struct stash *stash, unstash_t actor)
{
	struct flink_head *head = &stash->head;
	struct page *page;

	if (flink_empty(head))
		return 0;
	while (1) {
		page = __flink_next_entry(head, struct page, private);
		u64 *vec = page_address(page);
		u64 *top = page_address(page) + PAGE_SIZE;

		if (top == stash->top)
			top = stash->pos;
		for (; vec < top; vec++) {
			int err;
			if ((err = actor(sb, *vec)))
				return err;
		}
		if (flink_is_last(head))
			break;
		flink_del_next(head);
		__free_page(page);
	}
	stash->pos = page_address(page);
	return 0;
}

/*
 * Call actor() for each entries without freeing pages.
 */
int stash_walk(struct sb *sb, struct stash *stash, unstash_t actor)
{
	struct flink_head *head = &stash->head;
	struct page *page;

	if (flink_empty(head))
		return 0;

	struct link *link, *first;
	link = first = flink_next(head);
	do {
		page = __link_entry(link, struct page, private);
		u64 *vec = page_address(page);
		u64 *top = page_address(page) + PAGE_SIZE;

		if (top == stash->top)
			top = stash->pos;
		for (; vec < top; vec++) {
			int err;
			if ((err = actor(sb, *vec)))
				return err;
		}

		link = link->next;
	} while (link != first);

	return 0;
}

/* Deferred free blocks list */

int defer_bfree(struct stash *defree, block_t block, unsigned count)
{
	return stash_value(defree, ((u64)count << 48) + block);
}

void destroy_defer_bfree(struct stash *defree)
{
	empty_stash(defree);
}
