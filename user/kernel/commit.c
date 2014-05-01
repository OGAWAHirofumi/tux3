/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"
#ifdef __KERNEL__
#include <linux/kthread.h>
#include <linux/freezer.h>
#endif

#ifndef trace
#define trace trace_off
#endif

static void __delta_transition(struct sb *sb, struct delta_ref *delta_ref);
static void schedule_flush_delta(struct sb *sb);

/*
 * Need frontend modification of backend buffers. (modification
 * after latest delta commit and before unify).
 *
 * E.g. frontend modified backend buffers, stage_delta() of when
 * unify is called.
 */
#define ALLOW_FRONTEND_MODIFY

/* Initialize the lock and list */
static int init_sb(struct sb *sb)
{
	int i;

	/* Initialize sb */
	for (i = 0; i < ARRAY_SIZE(sb->delta_refs); i++)
		atomic_set(&sb->delta_refs[0].refcount, 0);

#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	init_rwsem(&sb->delta_lock);
#endif
	init_waitqueue_head(&sb->delta_event_wq);
	INIT_LIST_HEAD(&sb->orphan_add);
	INIT_LIST_HEAD(&sb->orphan_del);
	stash_init(&sb->defree);
	stash_init(&sb->deunify);
	INIT_LIST_HEAD(&sb->unify_buffers);

	INIT_LIST_HEAD(&sb->alloc_inodes);
	spin_lock_init(&sb->countmap_lock);
	spin_lock_init(&sb->forked_buffers_lock);
	init_link_circular(&sb->forked_buffers);
	spin_lock_init(&sb->dirty_inodes_lock);

	/* Initialize sb_delta_dirty */
	for (i = 0; i < ARRAY_SIZE(sb->s_ddc); i++)
		INIT_LIST_HEAD(&sb->s_ddc[i].dirty_inodes);

	sb->idefer_map = tux3_alloc_idefer_map();
	if (!sb->idefer_map)
		return -ENOMEM;

	return 0;
}

static void setup_roots(struct sb *sb, struct disksuper *super)
{
	u64 iroot_val = be64_to_cpu(super->iroot);
	u64 oroot_val = be64_to_cpu(sb->super.oroot);
	init_btree(itree_btree(sb), sb, unpack_root(iroot_val), &itree_ops);
	init_btree(otree_btree(sb), sb, unpack_root(oroot_val), &otree_ops);
}

static loff_t calc_maxbytes(loff_t blocksize)
{
	return min_t(loff_t, blocksize << MAX_BLOCKS_BITS, MAX_LFS_FILESIZE);
}

/* FIXME: Should goes into core */
static inline u64 roundup_pow_of_two64(u64 n)
{
	return 1ULL << fls64(n - 1);
}

/* Setup sb by on-disk super block */
static void __setup_sb(struct sb *sb, struct disksuper *super)
{
	sb->next_delta		= TUX3_INIT_DELTA;
	sb->unify		= TUX3_INIT_DELTA;
	sb->marshal_delta	= TUX3_INIT_DELTA - 1;
	sb->committed_delta	= TUX3_INIT_DELTA - 1;

	/* Setup initial delta_ref */
	__delta_transition(sb, &sb->delta_refs[0]);

	sb->blockbits = be16_to_cpu(super->blockbits);
	sb->volblocks = be64_to_cpu(super->volblocks);
	sb->version = 0;	/* FIXME: not yet implemented */

	sb->blocksize = 1 << sb->blockbits;
	sb->blockmask = (1 << sb->blockbits) - 1;
	sb->groupbits = 13; // FIXME: put in disk super?
	sb->volmask = roundup_pow_of_two64(sb->volblocks) - 1;
	sb->entries_per_node = calc_entries_per_node(sb->blocksize);
	/* Initialize base indexes for atable */
	atable_init_base(sb);

	/* vfs fields */
	vfs_sb(sb)->s_maxbytes = calc_maxbytes(sb->blocksize);

	/* Probably does not belong here (maybe metablock) */
	sb->freeinodes = MAX_INODES - be64_to_cpu(super->usedinodes);
	sb->freeblocks = sb->volblocks;
	sb->nextblock = be64_to_cpu(super->nextblock);
	sb->nextinum = TUX_NORMAL_INO;
	sb->atomdictsize = be64_to_cpu(super->atomdictsize);
	sb->atomgen = be32_to_cpu(super->atomgen);
	sb->freeatom = be32_to_cpu(super->freeatom);
	/* logchain and logcount are read from super directly */
	trace("blocksize %u, blockbits %u, blockmask %08x, groupbits %u",
	      sb->blocksize, sb->blockbits, sb->blockmask, sb->groupbits);
	trace("volblocks %Lu, volmask %Lx",
	      sb->volblocks, sb->volmask);
	trace("freeblocks %Lu, freeinodes %Lu, nextblock %Lu",
	      sb->freeblocks, sb->freeinodes, sb->nextblock);
	trace("atom_dictsize %Lu, freeatom %u, atomgen %u",
	      (s64)sb->atomdictsize, sb->freeatom, sb->atomgen);
	trace("logchain %Lu, logcount %u",
	      be64_to_cpu(super->logchain), be32_to_cpu(super->logcount));

	setup_roots(sb, super);
}

/* Initialize and setup sb by on-disk super block */
int setup_sb(struct sb *sb, struct disksuper *super)
{
	int err;

	err = init_sb(sb);
	if (err)
		return err;

	__setup_sb(sb, super);

	return 0;
}

/* Load on-disk super block, and call setup_sb() with it */
int load_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	int err;

	/* At least initialize sb, even if load is failed */
	err = init_sb(sb);
	if (err)
		return err;

	err = devio(READ, sb_dev(sb), SB_LOC, super, SB_LEN);
	if (err)
		return err;
	if (memcmp(super->magic, TUX3_MAGIC_STR, sizeof(super->magic)))
		return -EINVAL;

	__setup_sb(sb, super);

	return 0;
}

int save_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;

	super->blockbits = cpu_to_be16(sb->blockbits);
	super->volblocks = cpu_to_be64(sb->volblocks);

	/* Probably does not belong here (maybe metablock) */
	super->iroot = cpu_to_be64(pack_root(&itree_btree(sb)->root));
	super->oroot = cpu_to_be64(pack_root(&otree_btree(sb)->root));
	super->nextblock = cpu_to_be64(sb->nextblock);
	super->atomdictsize = cpu_to_be64(sb->atomdictsize);
	super->freeatom = cpu_to_be32(sb->freeatom);
	super->atomgen = cpu_to_be32(sb->atomgen);
	/* logchain and logcount are written to super directly */

	return devio(WRITE_SYNC | REQ_META, sb_dev(sb), SB_LOC, super, SB_LEN);
}

/* Delta transition */

static int relog_frontend_defer_as_bfree(struct sb *sb, u64 val)
{
	log_bfree_relog(sb, val & ~(-1ULL << 48), val >> 48);
	return 0;
}

static int relog_as_bfree(struct sb *sb, u64 val)
{
	log_bfree_relog(sb, val & ~(-1ULL << 48), val >> 48);
	return stash_value(&sb->defree, val);
}

/* Obsolete the old unify, then start the log of new unify */
static void new_cycle_log(struct sb *sb)
{
#if 0 /* ALLOW_FRONTEND_MODIFY */
	/*
	 * FIXME: we don't need to write the logs generated by
	 * frontend at all.  However, for now, we are writing those
	 * logs for debugging.
	 */

	/* Discard the logs generated by frontend. */
	log_finish(sb);
	log_finish_cycle(sb, 1);
#endif
	/* Initialize logcount to count log blocks on new unify cycle. */
	sb->super.logcount = 0;
}

/*
 * Flush a snapshot of the allocation map to disk.  Physical blocks for
 * the bitmaps and new or redirected bitmap btree nodes may be allocated
 * during the unify.  Any bitmap blocks that are (re)dirtied by these
 * allocations will be written out in the next unify cycle.
 */
static int unify_log(struct sb *sb)
{
	/* further block allocations belong to the next cycle */
	unsigned unify = sb->unify++;
	LIST_HEAD(orphan_add);
	LIST_HEAD(orphan_del);

	trace(">>>>>>>>> commit unify %u", unify);

	/*
	 * Orphan inodes are still living, or orphan inodes in
	 * sb->otree are dead. And logs will be obsoleted, so, we
	 * apply those to sb->otree.
	 */
	/* FIXME: orphan_add/del has no race with frontend for now */
	list_splice_init(&sb->orphan_add, &orphan_add);
	list_splice_init(&sb->orphan_del, &orphan_del);

	/* This is starting the new unify cycle of the log */
	new_cycle_log(sb);
	/* Add unify log as mark of new unify cycle. */
	log_unify(sb);
	/* Log to store freeblocks for flushing bitmap data */
	log_freeblocks(sb, sb->freeblocks);
#ifdef ALLOW_FRONTEND_MODIFY
	/*
	 * If frontend made defered bfree (i.e. it is not applied to
	 * bitmap yet), we have to re-log it on this cycle. Because we
	 * obsolete all logs in past.
	 */
	stash_walk(sb, &sb->defree, relog_frontend_defer_as_bfree);
#endif
	/*
	 * Re-logging defered bfree blocks after unify as defered
	 * bfree (LOG_BFREE_RELOG) after delta.  With this, we can
	 * obsolete log records on previous unify.
	 */
	unstash(sb, &sb->deunify, relog_as_bfree);

	/*
	 * Merge the dirty bnode buffers to volmap dirty list, and
	 * clean ->unify_buffers up before dirtying bnode buffers on
	 * this unify.  Later, bnode blocks will be flushed via
	 * volmap with leaves.
	 */
	list_splice_init(&sb->unify_buffers,
			 tux3_dirty_buffers(sb->volmap, TUX3_INIT_DELTA));
	/*
	 * tux3_mark_buffer_unify() doesn't dirty inode, so we make
	 * sure volmap is dirty for unify buffers, now.
	 *
	 * See comment in tux3_mark_buffer_unify().
	 */
	__tux3_mark_inode_dirty(sb->volmap, I_DIRTY_PAGES);

	/* Flush bitmap */
	trace("> flush bitmap %u", unify);
	tux3_flush_inode_internal(sb->bitmap, unify, REQ_META);
	trace("< done bitmap %u", unify);

	/* Flush bitmap */
	trace("> flush countmap %u", unify);
	tux3_flush_inode_internal(sb->countmap, unify, REQ_META);
	trace("< done countmap %u", unify);

	trace("> apply orphan inodes %u", unify);
	{
		int err;

		/*
		 * This defered deletion of orphan from sb->otree.
		 * It should be done before adding new orphan, because
		 * orphan_add may have same inum in orphan_del.
		 */
		err = tux3_unify_orphan_del(sb, &orphan_del);
		if (err)
			return err;

		/*
		 * This apply orphan inodes to sb->otree after flushed bitmap.
		 */
		err = tux3_unify_orphan_add(sb, &orphan_add);
		if (err)
			return err;
	}
	trace("< apply orphan inodes %u", unify);
	assert(list_empty(&orphan_add));
	assert(list_empty(&orphan_del));
	trace("<<<<<<<<< commit unify done %u", unify);

	return 0;
}

/* Apply frontend modifications to backend buffers, and flush data buffers. */
static int stage_delta(struct sb *sb, unsigned delta)
{
	int err;

	/* Flush inodes */
	err = tux3_flush_inodes(sb, delta);
	if (err)
		return err;

	/* Flush atable after inodes. Because inode deletion may dirty atable */
	err = tux3_flush_inode_internal(sb->atable, delta, 0);
	if (err)
		return err;
#if 0
	/* FIXME: we have to flush vtable somewhere */
	err = tux3_flush_inode_internal(sb->vtable, delta, 0);
	if (err)
		return err;
#endif
	return err;
}

static int write_btree(struct sb *sb, unsigned delta)
{
	/*
	 * If page is still dirtied by unify buffer,
	 * tux3_mark_buffer_atomic() doesn't dirty inode for delta, so
	 * we make sure volmap is dirty for delta buffers here.
	 *
	 * FIXME: better way to do?
	 */
	__tux3_mark_inode_dirty(sb->volmap, I_DIRTY_PAGES);

	/*
	 * Flush leaves (and if there is unify, bnodes too) blocks.
	 * FIXME: Now we are using TUX3_INIT_DELTA for leaves. Do
	 * we need to per delta dirty buffers?
	 */
	return tux3_flush_inode_internal(sb->volmap, TUX3_INIT_DELTA, REQ_META);
}

/* allocate and write log blocks */
static int write_log(struct sb *sb)
{
	/* Finish to logging in this delta */
	log_finish(sb);
	log_finish_cycle(sb, 0);

	return tux3_flush_inode_internal(sb->logmap, TUX3_INIT_DELTA, REQ_META);
}

static int apply_defered_bfree(struct sb *sb, u64 val)
{
	return bfree(sb, val & ~(-1ULL << 48), val >> 48);
}

static int commit_delta(struct sb *sb)
{
	trace("commit %i logblocks", be32_to_cpu(sb->super.logcount));
	int err = save_sb(sb);
	if (err)
		return err;

	/* Commit was finished, apply defered bfree. */
	return unstash(sb, &sb->defree, apply_defered_bfree);
}

static void post_commit(struct sb *sb, unsigned delta)
{
	/*
	 * Check referencer of forked buffer was gone, and can free.
	 * FIXME: is this right timing and place to do this?
	 */
	free_forked_buffers(sb, NULL, 0);

	tux3_clear_dirty_inodes(sb, delta);
}

static int need_unify(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 3);
}

enum unify_flags { NO_UNIFY, ALLOW_UNIFY, FORCE_UNIFY, };

/* For debugging */
void tux3_start_backend(struct sb *sb)
{
	assert(current->journal_info == NULL);
	current->journal_info = sb;
}

void tux3_end_backend(void)
{
	assert(current->journal_info);
	current->journal_info = NULL;
}

/* If true, it is under backend */
int tux3_under_backend(struct sb *sb)
{
	return current->journal_info == sb;
}

static int do_commit(struct sb *sb, enum unify_flags unify_flag)
{
	unsigned delta = sb->marshal_delta;
	struct iowait iowait;
	int err = 0;

	trace(">>>>>>>>> commit delta %u", delta);
	/* further changes of frontend belong to the next delta */
	tux3_start_backend(sb);

	/* Prepare to wait I/O */
	tux3_iowait_init(&iowait);
	sb->iowait = &iowait;

	/* Add delta log for debugging. */
	log_delta(sb);

	/*
	 * NOTE: This works like modification from frontend. (i.e. this
	 * may generate defree log which is not committed yet at unify.)
	 *
	 * - this is before unify to merge modifications to this
	 *   unify, and flush at once for optimization.
	 *
	 * - this is required to prevent unexpected buffer state for
	 *   cursor_redirect(). If we applied modification after
	 *   unify_log, it made unexpected dirty state (i.e. leaf is
	 *   still dirty, but parent was already cleaned.)
	 */
	err = stage_delta(sb, delta);
	if (err)
		goto error; /* FIXME: error handling */

	if ((unify_flag == ALLOW_UNIFY && need_unify(sb)) ||
	    unify_flag == FORCE_UNIFY) {
		err = unify_log(sb);
		if (err)
			goto error; /* FIXME: error handling */

		/* Add delta log for debugging. */
		log_delta(sb);
	}

	write_btree(sb, delta);
	write_log(sb);

	/* Wait I/O was submitted */
	tux3_iowait_wait(&iowait);

	/*
	 * Commit last block (for now, this is sync I/O).
	 *
	 * FIXME: If this is not data integrity write, we don't have
	 * to wait the commit block. The commit block just have to
	 * written before next block block. (But defree must be after
	 * commit block.)
	 */
	commit_delta(sb);
error:
	/* FIXME: what to do if error? */
	tux3_end_backend();
	trace("<<<<<<<<< commit done %u: err %d", delta, err);

	post_commit(sb, delta);
	trace("<<<<<<<<< post commit done %u", delta);

	return err;
}

/*
 * Flush delta work
 */

static int flush_delta(struct sb *sb)
{
	unsigned delta = sb->marshal_delta;
	int err;
#ifndef UNIFY_DEBUG
	enum unify_flags unify_flag = ALLOW_UNIFY;
#else
	struct delta_ref *delta_ref = sb->pending_delta;
	enum unify_flags unify_flag = delta_ref->unify_flag;
	sb->pending_delta = NULL;
#endif

	err = do_commit(sb, unify_flag);

	sb->committed_delta = delta;
	clear_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state);

	/* Wake up waiters for delta commit */
	wake_up_all(&sb->delta_event_wq);

	return err;
}

/*
 * Provide transaction boundary for delta, and delta transition request.
 */

/* Grab the reference of current delta */
static struct delta_ref *delta_get(struct sb *sb)
{
	struct delta_ref *delta_ref;
	/*
	 * Try to grab reference. If failed, retry.
	 *
	 * memory barrier pairs with __delta_transition(). But we never
	 * free ->current_delta, so we don't need rcu_read_lock().
	 */
	do {
		delta_ref = rcu_dereference_check(sb->current_delta, 1);
	} while (!atomic_inc_not_zero(&delta_ref->refcount));

	trace("delta %u, refcount %u",
	      delta_ref->delta, atomic_read(&delta_ref->refcount));

	return delta_ref;
}

/* Release the reference of delta */
static void delta_put(struct sb *sb, struct delta_ref *delta_ref)
{
	if (atomic_dec_and_test(&delta_ref->refcount)) {
		trace("set TUX3_COMMIT_PENDING_BIT");
		set_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state);
		schedule_flush_delta(sb);
	}

	trace("delta %u, refcount %u",
	      delta_ref->delta, atomic_read(&delta_ref->refcount));
}

/* Update current delta */
static void __delta_transition(struct sb *sb, struct delta_ref *delta_ref)
{
	/* Set the initial refcount is released by try_delta_transition(). */
	assert(atomic_read(&delta_ref->refcount) == 0);
	atomic_set(&delta_ref->refcount, 1);
	/* Assign the delta number */
	delta_ref->delta = sb->next_delta++;
#ifdef UNIFY_DEBUG
	delta_ref->unify_flag = ALLOW_UNIFY;
#endif

	/*
	 * Update current delta, then release reference.
	 *
	 * memory barrier pairs with delta_get().
	 */
	rcu_assign_pointer(sb->current_delta, delta_ref);
}

/*
 * Delta transition.
 *
 * Find the next delta_ref, then update current delta to it, and
 * release previous delta refcount.
 */
static void delta_transition(struct sb *sb)
{
	/*
	 * This is exclusive by TUX3_COMMIT_RUNNING_BIT (no writer),
	 * so rcu_dereference may not be needed.
	 */
	struct delta_ref *prev = rcu_dereference_check(sb->current_delta, 1);
	struct delta_ref *delta_ref;

	/* Find the next delta_ref */
	delta_ref = prev + 1;
	if (delta_ref == &sb->delta_refs[TUX3_MAX_DELTA])
		delta_ref = &sb->delta_refs[0];

	/* Update the current delta. */
	__delta_transition(sb, delta_ref);

	/* Set delta for marshal */
	sb->marshal_delta = prev->delta;
#ifdef UNIFY_DEBUG
	sb->pending_delta = prev;
#endif

	/* Release initial refcount after updated the current delta. */
	delta_put(sb, prev);

	trace("prev %u, next %u", prev->delta, delta_ref->delta);

	/* Wake up waiters for delta transition */
	wake_up_all(&sb->delta_event_wq);

#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	wait_event(sb->delta_event_wq,
		   test_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state));
#endif
}

#define delta_after_eq(a, b)			\
	(typecheck(unsigned, a) &&		\
	 typecheck(unsigned, b) &&		\
	 ((int)(a) - (int)(b) >= 0))

#include "commit_flusher.c"
#include "commit_flusher_hack.c"

int force_unify(struct sb *sb)
{
	return sync_current_delta(sb, FORCE_UNIFY);
}

int force_delta(struct sb *sb)
{
	return sync_current_delta(sb, NO_UNIFY);
}

unsigned tux3_get_current_delta(void)
{
	struct delta_ref *delta_ref = current->journal_info;
	assert(delta_ref != NULL);
	return delta_ref->delta;
}

/* Choice sb->delta or sb->unify from inode */
unsigned tux3_inode_delta(struct inode *inode)
{
	unsigned delta;

	switch (tux_inode(inode)->inum) {
	case TUX_VOLMAP_INO:
	case TUX_LOGMAP_INO:
		/*
		 * Note: volmap are special, and has both of
		 * TUX3_INIT_DELTA and sb->unify. So TUX3_INIT_DELTA
		 * can be incorrect if delta was used for buffer.
		 * Note: logmap is similar to volmap, but it doesn't
		 * have sb->unify buffers.
		 */
		delta = TUX3_INIT_DELTA;
		break;
	case TUX_BITMAP_INO:
	case TUX_COUNTMAP_INO:
		delta = tux_sb(inode->i_sb)->unify;
		break;
	default:
		delta = tux3_get_current_delta();
		break;
	}

	return delta;
}

/*
 * This is used to avoid to run backend (if disabled asynchronous
 * backend), and never be blocked. This is used in atomic context, or
 * from backend task to avoid to run backend recursively.
 */
void change_begin_atomic(struct sb *sb)
{
	assert(current->journal_info == NULL);
	current->journal_info = delta_get(sb);
}

/* change_end() without starting do_commit(). Use this only if necessary. */
void change_end_atomic(struct sb *sb)
{
	struct delta_ref *delta_ref = current->journal_info;
	assert(delta_ref != NULL);
	current->journal_info = NULL;
	delta_put(sb, delta_ref);
}

/*
 * This is used for nested change_begin/end. We should not use this
 * usually (nesting change_begin/end is wrong for normal operations).
 *
 * For now, this is only used for ->evict_inode() debugging, and page fault.
 */
void change_begin_atomic_nested(struct sb *sb, void **ptr)
{
	*ptr = current->journal_info;
	current->journal_info = NULL;
	change_begin_atomic(sb);
}

void change_end_atomic_nested(struct sb *sb, void *ptr)
{
	change_end_atomic(sb);
	current->journal_info = ptr;
}

static int need_delta(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 10);
}

/*
 * Normal version of change_begin/end. If there is no special
 * requirement, we should use this version.
 *
 * This checks backend job and run if disabled asynchronous backend,
 * and blocked if disabled asynchronous backend and backend is
 * running.
 */
void change_begin(struct sb *sb)
{
#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	down_read(&sb->delta_lock);
#endif
	change_begin_atomic(sb);
}

int change_end(struct sb *sb)
{
	int err = 0;

	change_end_atomic(sb);
#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	up_read(&sb->delta_lock);

	down_write(&sb->delta_lock);
#endif
	if (need_delta(sb))
		try_delta_transition(sb);

#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	err = flush_pending_delta(sb);
	up_write(&sb->delta_lock);
#endif

	return err;
}

/*
 * This is used for simplify the error path, or separates big chunk to
 * small chunk in loop.
 *
 * E.g. the following
 *
 * change_begin()
 * while (stop) {
 * 	change_begin_if_need()
 * 	if (do_something() < 0)
 * 		break;
 * 	change_end_if_need()
 * }
 * change_end_if_need()
 */
void change_begin_if_needed(struct sb *sb, int need_sep)
{
	if (current->journal_info == NULL)
		change_begin(sb);
	else if (need_sep) {
		change_end(sb);
		change_begin(sb);
	}
}

void change_end_if_needed(struct sb *sb)
{
	if (current->journal_info)
		change_end(sb);
}
