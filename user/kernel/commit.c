/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

void setup_sb(struct sb *sb, struct disksuper *super)
{
	sb->blockbits = from_be_u16(super->blockbits);
	sb->blocksize = 1 << sb->blockbits;
	sb->blockmask = (1 << sb->blockbits) - 1;
	/* FIXME: those should be initialized based on blocksize. */
	sb->entries_per_node = calc_entries_per_node(sb->blocksize);
	sb->max_inodes_per_block = sb->blocksize / 64;
//	sb->version;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->volblocks = from_be_u64(super->volblocks);
#ifdef ATOMIC
	sb->freeblocks = sb->volblocks;
#else
	sb->freeblocks = from_be_u64(super->freeblocks);
#endif
	sb->nextalloc = from_be_u64(super->nextalloc);
	sb->atomgen = from_be_u32(super->atomgen);
	sb->freeatom = from_be_u32(super->freeatom);
	sb->dictsize = from_be_u64(super->dictsize);
	sb->logchain = from_be_u64(super->logchain);
	trace("blocksize %u, blockbits %u, blockmask %08x",
	      sb->blocksize, sb->blockbits, sb->blockmask);
	trace("volblocks %Lu, freeblocks %Lu, nextalloc %Lu",
	      (L)sb->volblocks, (L)sb->freeblocks, (L)sb->nextalloc);
	trace("freeatom %u, atomgen %u", sb->freeatom, sb->atomgen);
	trace("dictsize %Lu", (L)sb->dictsize);
	trace("logchain %Lu", (L)sb->logchain);
}

int load_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	int err;

	err = devio(READ, sb_dev(sb), SB_LOC, super, SB_LEN);
	if (err)
		return err;
	if (memcmp(super->magic, TUX3_MAGIC, sizeof(super->magic)))
		return -EINVAL;

	setup_sb(sb, super);
	return 0;
}

int save_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;

	super->blockbits = to_be_u16(sb->blockbits);
	super->volblocks = to_be_u64(sb->volblocks);
#ifndef ATOMIC
	super->freeblocks = to_be_u64(sb->freeblocks); // probably does not belong here
#endif
	super->nextalloc = to_be_u64(sb->nextalloc); // probably does not belong here
	super->atomgen = to_be_u32(sb->atomgen); // probably does not belong here
	super->freeatom = to_be_u32(sb->freeatom); // probably does not belong here
	super->dictsize = to_be_u64(sb->dictsize); // probably does not belong here
	super->iroot = to_be_u64(pack_root(&itable_btree(sb)->root));
	super->logchain = to_be_u64(sb->logchain);
	return devio(WRITE, sb_dev(sb), SB_LOC, super, SB_LEN);
}

int load_itable(struct sb *sb)
{
	u64 iroot_val = from_be_u64(sb->super.iroot);

	init_btree(itable_btree(sb), sb, unpack_root(iroot_val), &itable_ops);
	return 0;
}

void clean_buffer(struct buffer_head *buffer)
{
#ifdef __KERNEL__
	set_buffer_uptodate(buffer);
#else
	/* Is this forked buffer? */
	if (hlist_unhashed(&buffer->hashlink)) {
		set_buffer_clean(buffer);
		blockput(buffer);
		evict_buffer(buffer);
	} else
		set_buffer_clean(buffer);
#endif
}

/* Delta transition */

static int flush_buffer_list(struct sb *sb, struct list_head *head)
{
#ifndef __KERNEL__
	/* FIXME: code should be share with flush_buffers() */
	struct buffer_head *buffer;

	while (!list_empty(head)) {
		buffer = list_entry(head->next, struct buffer_head, link);
		trace(">>> flush buffer %Lx:%Lx", (L)tux_inode(buffer_inode(buffer))->inum, (L)bufindex(buffer));
		// mapping, index set but not hashed in mapping
		buffer->map->io(buffer, 1);
		evict_buffer(buffer);
	}
#endif
	return 0;
}

static int relog_as_bfree(struct sb *sb, u64 val)
{
	log_bfree_relog(sb, val & ~(-1ULL << 48), val >> 48);
	return stash_value(&sb->defree, val);
}

/* Obsolete the old rollup, then start the log of new rollup */
static void new_cycle_log(struct sb *sb)
{
	/* If sb->logbuf != NULL, sb->lognext is pointing next log */
	sb->logbase = sb->lognext - (sb->logbuf != NULL);
}

/*
 * Flush a snapshot of the allocation map to disk.  Physical blocks for
 * the bitmaps and new or redirected bitmap btree nodes may be allocated
 * during the rollup.  Any bitmap blocks that are (re)dirtied by these
 * allocations will be written out in the next rollup cycle.
 */
static int rollup_log(struct sb *sb)
{
	trace(">>>>>>>>> commit rollup %u", sb->rollup);
	/* further block allocations belong to the next cycle */
	sb->rollup++;

#ifndef __KERNEL__
	/*
	 * sb->rollup was incremented, so block fork may occur from here,
	 * so before block fork was occured, cleans map->dirty list.
	 * [If we have two lists per map for dirty, we may not need this.]
	 */
	LIST_HEAD(io_buffers);
	list_splice_init(&mapping(sb->bitmap)->dirty, &io_buffers);

	/* This is starting the new rollup cycle of the log */
	new_cycle_log(sb);
	/* Add rollup log as mark of new rollup cycle. */
	log_rollup(sb);
	/* Log to store freeblocks for flushing bitmap data */
	log_freeblocks(sb, sb->freeblocks);

	/*
	 * Re-logging defered bfree blocks after rollup as defered
	 * bfree (LOG_BFREE_RELOG) after delta.  With this, we can
	 * obsolete log records on previous rollup.
	 */
	unstash(sb, &sb->derollup, relog_as_bfree);

	/* bnode blocks */
	trace("> flush pinned buffers %u", sb->rollup);
	flush_buffer_list(sb, &sb->pinned);
	trace("< done pinned buffers %u", sb->rollup);

	/* map dirty bitmap blocks to disk and write out */
	trace("> flush bitmap data %u", sb->rollup);
	struct buffer_head *buffer, *safe;
	list_for_each_entry_safe(buffer, safe, &io_buffers, link) {
		int err = write_bitmap(buffer);
		if (err)
			return err;
	}
	trace("< done bitmap data %u", sb->rollup);
	trace("> flush bitmap inode %u", sb->rollup);
	{
		int err = write_inode(sb->bitmap);
		if (err)
			return err;
	}
	trace("< done bitmap inode %u", sb->rollup);
	assert(list_empty(&io_buffers));
#endif
	trace("<<<<<<<<< commit rollup done %u", sb->rollup - 1);

	return 0;
}

static int stage_delta(struct sb *sb)
{
	int err;

	/* flush inodes */
	err = sync_inodes(sb);
	if (err)
		return err;
#if 1
	/* flush leaf blocks */
	return sync_inode(sb->volmap);
#else
	/* what is this? */
	/* leaf blocks */
	return flush_buffer_list(sb, &sb->commit);
#endif
}

/* allocate and write log blocks */
static int write_log(struct sb *sb)
{
	/* Finish to logging in this delta */
	log_finish(sb);

	for (unsigned index = sb->logthis; index < sb->lognext; index++) {
		block_t block;
		int err = balloc(sb, 1, &block);
		if (err)
			return err;
		struct buffer_head *buffer = blockget(mapping(sb->logmap), index);
		if (!buffer) {
			bfree(sb, block, 1);
			return -ENOMEM;
		}
		struct logblock *log = bufdata(buffer);
		assert(log->magic == to_be_u16(TUX3_MAGIC_LOG));
		log->logchain = to_be_u64(sb->logchain);
		err = blockio(WRITE, buffer, block);
		if (err) {
			blockput(buffer);
			bfree(sb, block, 1);
			return err;
		}

		/*
		 * We can obsolete the log blocks after next rollup
		 * by LOG_BFREE_RELOG.
		 */
		defer_bfree(&sb->derollup, block, 1);

		blockput(buffer);
		trace("logchain %lld", (L)block);
		sb->logchain = block;
	}
	sb->logthis = sb->lognext;

	return 0;
}

/* userland only */
int apply_defered_bfree(struct sb *sb, u64 val)
{
	return bfree(sb, val & ~(-1ULL << 48), val >> 48);
}

static int commit_delta(struct sb *sb)
{
	trace("commit %i logblocks", sb->lognext - sb->logbase);
	/* FIXME: Move to save_sb()? Handle wraparound of lognext, etc */
	sb->super.logcount = to_be_u32(sb->lognext - sb->logbase);

	int err = save_sb(sb);
	if (err)
		return err;

	/* Commit was finished, apply defered bfree. */
	return unstash(sb, &sb->defree, apply_defered_bfree);
}

static int need_delta(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 10);
}

static int need_rollup(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 3);
}

enum rollup_flags { NO_ROLLUP, ALLOW_ROLLUP, FORCE_ROLLUP, };

/* must hold down_write(&sb->delta_lock) */
static int do_commit(struct sb *sb, enum rollup_flags rollup_flag)
{
	int err = 0;

	trace(">>>>>>>>> commit delta %u", sb->delta);
	/* further changes of frontend belong to the next delta */
	sb->delta++;

	if ((rollup_flag == ALLOW_ROLLUP && need_rollup(sb)) ||
	    rollup_flag == FORCE_ROLLUP) {
		err = rollup_log(sb);
		if (err)
			return err;
	}

	/* Add delta log as an initial log for debugging. */
	log_delta(sb);

	stage_delta(sb);
	write_log(sb);
	commit_delta(sb);
	trace("<<<<<<<<< commit done %u", sb->delta - 1);

	return err; /* FIXME: error handling */
}

/* FIXME: quickly designed, rethink this. */
int force_rollup(struct sb *sb)
{
	int err;

	down_write(&sb->delta_lock);
	err = do_commit(sb, FORCE_ROLLUP);
	up_write(&sb->delta_lock);

	return err;
}

/* FIXME: quickly designed, rethink this. */
int force_delta(struct sb *sb)
{
	int err;

	down_write(&sb->delta_lock);
	err = do_commit(sb, NO_ROLLUP);
	up_write(&sb->delta_lock);

	return err;
}

int change_begin(struct sb *sb)
{
#ifndef __KERNEL__
	down_read(&sb->delta_lock);
#endif
	return 0;
}

int change_end(struct sb *sb)
{
	int err = 0;
#ifndef __KERNEL__
	if (!need_delta(sb)) {
		up_read(&sb->delta_lock);
		return 0;
	}
	unsigned delta = sb->delta;
	up_read(&sb->delta_lock);

	down_write(&sb->delta_lock);
	/* FIXME: error handling */
	if (sb->delta == delta)
		err = do_commit(sb, ALLOW_ROLLUP);
	up_write(&sb->delta_lock);
#endif
	return err;
}

#ifdef __KERNEL__
static void *useme[] = { new_cycle_log, need_delta, do_commit, useme };
#endif
