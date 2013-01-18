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
#define trace trace_on
#endif

static void __delta_transition(struct sb *sb, struct delta_ref *delta_ref);

/*
 * Need frontend modification of backend buffers. (modification
 * after latest delta commit and before rollup).
 *
 * E.g. frontend modified backend buffers, stage_delta() of when
 * rollup is called.
 */
#define ALLOW_FRONTEND_MODIFY

/* Initialize the lock and list */
static void init_sb(struct sb *sb)
{
	int i;

	/* Initialize sb */
	for (i = 0; i < ARRAY_SIZE(sb->delta_refs); i++)
		atomic_set(&sb->delta_refs[0].refcount, 0);

#ifdef DISABLE_ASYNC_BACKEND
	init_rwsem(&sb->delta_lock);
#endif
	init_waitqueue_head(&sb->delta_event_wq);
	mutex_init(&sb->loglock);
	INIT_LIST_HEAD(&sb->orphan_add);
	INIT_LIST_HEAD(&sb->orphan_del);
	stash_init(&sb->defree);
	stash_init(&sb->derollup);
	INIT_LIST_HEAD(&sb->rollup_buffers);

	INIT_LIST_HEAD(&sb->alloc_inodes);
	spin_lock_init(&sb->forked_buffers_lock);
	init_link_circular(&sb->forked_buffers);
	spin_lock_init(&sb->dirty_inodes_lock);

	/* Initialize sb_delta_dirty */
	for (i = 0; i < ARRAY_SIZE(sb->s_ddc); i++)
		INIT_LIST_HEAD(&sb->s_ddc[i].dirty_inodes);
}

static void setup_roots(struct sb *sb, struct disksuper *super)
{
	u64 iroot_val = be64_to_cpu(super->iroot);
	u64 oroot_val = be64_to_cpu(sb->super.oroot);
	init_btree(itable_btree(sb), sb, unpack_root(iroot_val), &itable_ops);
	init_btree(otable_btree(sb), sb, unpack_root(oroot_val), &otable_ops);
}

static loff_t calc_maxbytes(loff_t blocksize)
{
	return min_t(loff_t, blocksize << MAX_BLOCKS_BITS, MAX_LFS_FILESIZE);
}

/* Setup sb by on-disk super block */
static void __setup_sb(struct sb *sb, struct disksuper *super)
{
	sb->next_delta		= TUX3_INIT_DELTA;
	sb->rollup		= TUX3_INIT_DELTA;
	sb->marshal_delta	= TUX3_INIT_DELTA - 1;
	sb->committed_delta	= TUX3_INIT_DELTA - 1;

	/* Setup initial delta_ref */
	__delta_transition(sb, &sb->delta_refs[0]);

	sb->blockbits = be16_to_cpu(super->blockbits);
	sb->volblocks = be64_to_cpu(super->volblocks);
	sb->version = 0;	/* FIXME: not yet implemented */

	sb->blocksize = 1 << sb->blockbits;
	sb->blockmask = (1 << sb->blockbits) - 1;
	sb->entries_per_node = calc_entries_per_node(sb->blocksize);
	/* Initialize base indexes for atable */
	atable_init_base(sb);

	/* vfs fields */
	vfs_sb(sb)->s_maxbytes = calc_maxbytes(sb->blocksize);

	/* Probably does not belong here (maybe metablock) */
#ifdef ATOMIC
	sb->freeblocks = sb->volblocks;
#else
	sb->freeblocks = be64_to_cpu(super->freeblocks);
#endif
	sb->nextalloc = be64_to_cpu(super->nextalloc);
	sb->atomdictsize = be64_to_cpu(super->atomdictsize);
	sb->atomgen = be32_to_cpu(super->atomgen);
	sb->freeatom = be32_to_cpu(super->freeatom);
	/* logchain and logcount are read from super directly */
	trace("blocksize %u, blockbits %u, blockmask %08x",
	      sb->blocksize, sb->blockbits, sb->blockmask);
	trace("volblocks %Lu, freeblocks %Lu, nextalloc %Lu",
	      sb->volblocks, sb->freeblocks, sb->nextalloc);
	trace("atom_dictsize %Lu, freeatom %u, atomgen %u",
	      (s64)sb->atomdictsize, sb->freeatom, sb->atomgen);
	trace("logchain %Lu, logcount %u",
	      be64_to_cpu(super->logchain), be32_to_cpu(super->logcount));

	setup_roots(sb, super);
}

/* Initialize and setup sb by on-disk super block */
void setup_sb(struct sb *sb, struct disksuper *super)
{
	init_sb(sb);
	__setup_sb(sb, super);
}

/* Load on-disk super block, and call setup_sb() with it */
int load_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	int err;

	/* At least initialize sb, even if load is failed */
	init_sb(sb);

	err = devio(READ, sb_dev(sb), SB_LOC, super, SB_LEN);
	if (err)
		return err;
	if (memcmp(super->magic, TUX3_MAGIC, sizeof(super->magic)))
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
	super->iroot = cpu_to_be64(pack_root(&itable_btree(sb)->root));
	super->oroot = cpu_to_be64(pack_root(&otable_btree(sb)->root));
#ifndef ATOMIC
	super->freeblocks = cpu_to_be64(sb->freeblocks);
#endif
	super->nextalloc = cpu_to_be64(sb->nextalloc);
	super->atomdictsize = cpu_to_be64(sb->atomdictsize);
	super->freeatom = cpu_to_be32(sb->freeatom);
	super->atomgen = cpu_to_be32(sb->atomgen);
	/* logchain and logcount are written to super directly */

	return devio(WRITE, sb_dev(sb), SB_LOC, super, SB_LEN);
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

/* Obsolete the old rollup, then start the log of new rollup */
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
	log_finish_cycle(sb);
#endif
	/* Initialize logcount to count log blocks on new rollup cycle. */
	sb->super.logcount = 0;
}

/*
 * Flush a snapshot of the allocation map to disk.  Physical blocks for
 * the bitmaps and new or redirected bitmap btree nodes may be allocated
 * during the rollup.  Any bitmap blocks that are (re)dirtied by these
 * allocations will be written out in the next rollup cycle.
 */
static int rollup_log(struct sb *sb)
{
	/* further block allocations belong to the next cycle */
	unsigned rollup = sb->rollup++;
	LIST_HEAD(orphan_add);
	LIST_HEAD(orphan_del);

	trace(">>>>>>>>> commit rollup %u", rollup);

	/*
	 * Orphan inodes are still living, or orphan inodes in
	 * sb->otable are dead. And logs will be obsoleted, so, we
	 * apply those to sb->otable.
	 */
	/* FIXME: orphan_add/del has no race with frontend for now */
	list_splice_init(&sb->orphan_add, &orphan_add);
	list_splice_init(&sb->orphan_del, &orphan_del);

	/* This is starting the new rollup cycle of the log */
	new_cycle_log(sb);
	/* Add rollup log as mark of new rollup cycle. */
	log_rollup(sb);
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
	 * Re-logging defered bfree blocks after rollup as defered
	 * bfree (LOG_BFREE_RELOG) after delta.  With this, we can
	 * obsolete log records on previous rollup.
	 */
	unstash(sb, &sb->derollup, relog_as_bfree);

	/*
	 * Merge the dirty bnode buffers to volmap dirty list, and
	 * clean ->rollup_buffers up before dirtying bnode buffers on
	 * this rollup.  Later, bnode blocks will be flushed via
	 * volmap with leaves.
	 */
	list_splice_init(&sb->rollup_buffers,
			 tux3_dirty_buffers(sb->volmap, TUX3_INIT_DELTA));

	/* Flush bitmap */
	trace("> flush bitmap %u", rollup);
	tux3_flush_inode_internal(sb->bitmap, rollup);
	trace("< done bitmap %u", rollup);

	trace("> apply orphan inodes %u", rollup);
	{
		int err;

		/*
		 * This defered deletion of orphan from sb->otable.
		 * It should be done before adding new orphan, because
		 * orphan_add may have same inum in orphan_del.
		 */
		err = tux3_rollup_orphan_del(sb, &orphan_del);
		if (err)
			return err;

		/*
		 * This apply orphan inodes to sb->otable after flushed bitmap.
		 */
		err = tux3_rollup_orphan_add(sb, &orphan_add);
		if (err)
			return err;
	}
	trace("< apply orphan inodes %u", rollup);
	assert(list_empty(&orphan_add));
	assert(list_empty(&orphan_del));
	trace("<<<<<<<<< commit rollup done %u", rollup);

	return 0;
}

/* Apply frontend modifications to backend buffers, and flush data buffers. */
static int stage_delta(struct sb *sb, unsigned delta)
{
	/* flush inodes */
	return tux3_flush_inodes(sb, delta);
}

static int write_btree(struct sb *sb, unsigned delta)
{
	/*
	 * Flush leaves (and if there is rollup, bnodes too) blocks.
	 * FIXME: Now we are using TUX3_INIT_DELTA for leaves. Do
	 * we need to per delta dirty buffers?
	 */
	return tux3_flush_inode_internal(sb->volmap, TUX3_INIT_DELTA);
}

/* allocate and write log blocks */
static int write_log(struct sb *sb)
{
	unsigned index, logcount;

	/* Finish to logging in this delta */
	log_finish(sb);

	/* FIXME: maybe, we should use bufvec to write log blocks at once */
	for (index = 0; index < sb->lognext; index++) {
		block_t block;
		int err = balloc(sb, 1, &block);
		if (err)
			return err;
		struct buffer_head *buffer = blockget(mapping(sb->logmap), index);
		assert(buffer);
		struct logblock *log = bufdata(buffer);
		assert(log->magic == cpu_to_be16(TUX3_MAGIC_LOG));
		log->logchain = sb->super.logchain;
		err = blockio(WRITE, sb, buffer, block);
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
		trace("logchain %lld", block);
		sb->super.logchain = cpu_to_be64(block);
	}

	/* Add count of log on this delta to rollup logcount */
	logcount = be32_to_cpu(sb->super.logcount);
	logcount += log_finish_cycle(sb);

	sb->super.logcount = cpu_to_be32(logcount);

	return 0;
}

/* userland only */
int apply_defered_bfree(struct sb *sb, u64 val)
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

static int need_rollup(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 3);
}

enum rollup_flags { NO_ROLLUP, ALLOW_ROLLUP, FORCE_ROLLUP, };

static int do_commit(struct sb *sb, enum rollup_flags rollup_flag)
{
	unsigned delta = sb->marshal_delta;
	struct iowait iowait;
	int err = 0;

	trace(">>>>>>>>> commit delta %u", delta);
	/* further changes of frontend belong to the next delta */

	/* Prepare to wait I/O */
	tux3_iowait_init(&iowait);
	sb->iowait = &iowait;

	/* Add delta log for debugging. */
	log_delta(sb);

	/*
	 * NOTE: This works like modification from frontend. (i.e. this
	 * may generate defree log which is not committed yet at rollup.)
	 *
	 * - this is before rollup to merge modifications to this
	 *   rollup, and flush at once for optimization.
	 *
	 * - this is required to prevent unexpected buffer state for
	 *   cursor_redirect(). If we applied modification after
	 *   rollup_log, it made unexpected dirty state (i.e. leaf is
	 *   still dirty, but parent was already cleaned.)
	 */
	err = stage_delta(sb, delta);
	if (err)
		return err;

	if ((rollup_flag == ALLOW_ROLLUP && need_rollup(sb)) ||
	    rollup_flag == FORCE_ROLLUP) {
		err = rollup_log(sb);
		if (err)
			return err;

		/* Add delta log for debugging. */
		log_delta(sb);
	}

	write_btree(sb, delta);
	write_log(sb);
	/* Wait I/O was submitted */
	tux3_iowait_wait(&iowait);
	/* Commit last block (for now, this is sync I/O) */
	commit_delta(sb);
	trace("<<<<<<<<< commit done %u", delta);

	post_commit(sb, delta);
	trace("<<<<<<<<< post commit done %u", delta);

	return err; /* FIXME: error handling */
}

/*
 * Flush delta work
 */

static int flush_delta(struct sb *sb)
{
	unsigned delta = sb->marshal_delta;
	int err;
#ifndef ROLLUP_DEBUG
	enum rollup_flags rollup_flag = ALLOW_ROLLUP;
#else
	struct delta_ref *delta_ref = sb->pending_delta;
	enum rollup_flags rollup_flag = delta_ref->rollup_flag;
	sb->pending_delta = NULL;
#endif

	err = do_commit(sb, rollup_flag);

	sb->committed_delta = delta;
	clear_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state);

	/* Wake up waiters for delta commit */
	wake_up_all(&sb->delta_event_wq);

	return err;
}

#ifndef DISABLE_ASYNC_BACKEND
static int flush_delta_work(void *data)
{
	struct sb *sb = data;
	int err;

	set_freezable();

	/*
	 * Our parent may run at a different priority, just set us to normal
	 */
	set_user_nice(current, 0);

	while (!kthread_freezable_should_stop(NULL)) {
		if (test_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state)) {
			clear_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state);

			err = flush_delta(sb);
			/* FIXME: error handling */
		}

		set_current_state(TASK_INTERRUPTIBLE);
		if (!test_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state) &&
		    !kthread_should_stop())
			schedule();
		__set_current_state(TASK_RUNNING);
	}

	return 0;
}

static void schedule_flush_delta(struct sb *sb)
{
	wake_up_process(sb->flush_task);
}

int tux3_init_flusher(struct sb *sb)
{
	struct task_struct *task;
	char b[BDEVNAME_SIZE];

	bdevname(vfs_sb(sb)->s_bdev, b);

	/* FIXME: we should use normal bdi-writeback by changing core */
	task = kthread_run(flush_delta_work, sb, "tux3/%s", b);
	if (IS_ERR(task))
		return PTR_ERR(task);

	sb->flush_task = task;

	return 0;
}

void tux3_exit_flusher(struct sb *sb)
{
	if (sb->flush_task) {
		kthread_stop(sb->flush_task);
		sb->flush_task = NULL;
	}
}

static int flush_pending_delta(struct sb *sb)
{
	return 0;
}
#else /* !DISABLE_ASYNC_BACKEND */
static void schedule_flush_delta(struct sb *sb)
{
}

int tux3_init_flusher(struct sb *sb)
{
	return 0;
}

void tux3_exit_flusher(struct sb *sb)
{
}

static int flush_pending_delta(struct sb *sb)
{
	int err = 0;

	if (!test_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state))
		goto out;

	if (test_and_clear_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state))
		err = flush_delta(sb);
out:
	return err;
}
#endif /* !DISABLE_ASYNC_BACKEND */

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
		/* Start the flusher for pending delta */
		schedule_flush_delta(sb);
#ifdef DISABLE_ASYNC_BACKEND
		/* Wake up waiters for pending marshal delta */
		wake_up_all(&sb->delta_event_wq);
#endif
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
#ifdef ROLLUP_DEBUG
	delta_ref->rollup_flag = ALLOW_ROLLUP;
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
#ifdef ROLLUP_DEBUG
	sb->pending_delta = prev;
#endif

	/* Release initial refcount after updated the current delta. */
	delta_put(sb, prev);

	trace("prev %u, next %u", prev->delta, delta_ref->delta);

	/* Wake up waiters for delta transition */
	wake_up_all(&sb->delta_event_wq);

#ifdef DISABLE_ASYNC_BACKEND
	wait_event(sb->delta_event_wq,
		   test_bit(TUX3_COMMIT_PENDING_BIT, &sb->backend_state));
#endif
}

/* Try delta transition */
static void try_delta_transition(struct sb *sb)
{
	trace("marshal %u, backend_state %lx",
	      sb->marshal_delta, sb->backend_state);
	if (!test_and_set_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state))
		delta_transition(sb);
}

#define delta_after_eq(a, b)			\
	(typecheck(unsigned, a) &&		\
	 typecheck(unsigned, b) &&		\
	 ((int)(a) - (int)(b) >= 0))

/* Do the delta transition until specified delta */
static int try_delta_transition_until_delta(struct sb *sb, unsigned delta)
{
	trace("delta %u, marshal %u, backend_state %lx",
	      delta, sb->marshal_delta, sb->backend_state);

	/* Already delta transition was started for delta */
	if (delta_after_eq(sb->marshal_delta, delta))
		return 1;

	if (!test_and_set_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state)) {
		/* Recheck after grabed TUX3_COMMIT_RUNNING_BIT */
		if (delta_after_eq(sb->marshal_delta, delta)) {
			clear_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state);
			return 1;
		}

		delta_transition(sb);
	}

	return delta_after_eq(sb->marshal_delta, delta);
}

/* Advance delta transition until specified delta */
static int wait_for_transition(struct sb *sb, unsigned delta)
{
	return wait_event_killable(sb->delta_event_wq,
				   try_delta_transition_until_delta(sb, delta));
}

static int try_flush_pending_until_delta(struct sb *sb, unsigned delta)
{
	trace("delta %u, committed %u, backend_state %lx",
	      delta, sb->committed_delta, sb->backend_state);

	if (!delta_after_eq(sb->committed_delta, delta))
		flush_pending_delta(sb);

	return delta_after_eq(sb->committed_delta, delta);
}

static int wait_for_commit(struct sb *sb, unsigned delta)
{
	return wait_event_killable(sb->delta_event_wq,
				   try_flush_pending_until_delta(sb, delta));
}

static int sync_current_delta(struct sb *sb, enum rollup_flags rollup_flag)
{
	struct delta_ref *delta_ref;
	unsigned delta;
	int err = 0;

#ifdef DISABLE_ASYNC_BACKEND
	down_write(&sb->delta_lock);
#endif
	/* Get delta that have to write */
	delta_ref = delta_get(sb);
#ifdef ROLLUP_DEBUG
	delta_ref->rollup_flag = rollup_flag;
#endif
	delta = delta_ref->delta;
	delta_put(sb, delta_ref);

	trace("delta %u", delta);

	/* Make sure the delta transition was done for current delta */
	err = wait_for_transition(sb, delta);
	if (err)
		return err;
	assert(delta_after_eq(sb->marshal_delta, delta));

	/* Wait until committing the current delta */
	err = wait_for_commit(sb, delta);
	assert(err || delta_after_eq(sb->committed_delta, delta));
#ifdef DISABLE_ASYNC_BACKEND
	up_write(&sb->delta_lock);
#endif

	return err;
}

#ifdef ATOMIC
int force_rollup(struct sb *sb)
{
	return sync_current_delta(sb, FORCE_ROLLUP);
}

int force_delta(struct sb *sb)
{
	return sync_current_delta(sb, NO_ROLLUP);
}
#endif /* !ATOMIC */

unsigned tux3_get_current_delta(void)
{
	struct delta_ref *delta_ref = current->journal_info;
	assert(delta_ref != NULL);
	return delta_ref->delta;
}

/* Choice sb->delta or sb->rollup from inode */
unsigned tux3_inode_delta(struct inode *inode)
{
	unsigned delta;

	switch (tux_inode(inode)->inum) {
	case TUX_VOLMAP_INO:
		/*
		 * Note: volmap are special, and has both of
		 * TUX3_INIT_DELTA and sb->rollup. So TUX3_INIT_DELTA
		 * can be incorrect if delta was used for buffer.
		 */
		delta = TUX3_INIT_DELTA;
		break;
	case TUX_BITMAP_INO:
		delta = tux_sb(inode->i_sb)->rollup;
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
 * For now, this is only used for ->evict_inode() debugging.
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
#ifdef DISABLE_ASYNC_BACKEND
	down_read(&sb->delta_lock);
#endif
	change_begin_atomic(sb);
}

int change_end(struct sb *sb)
{
	int err = 0;

	change_end_atomic(sb);
#ifdef DISABLE_ASYNC_BACKEND
	up_read(&sb->delta_lock);
#endif

#ifdef DISABLE_ASYNC_BACKEND
	down_write(&sb->delta_lock);
#endif
	if (need_delta(sb))
		try_delta_transition(sb);

	err = flush_pending_delta(sb);
#ifdef DISABLE_ASYNC_BACKEND
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
void change_begin_if_needed(struct sb *sb)
{
	if (current->journal_info == NULL)
		change_begin(sb);
}

void change_end_if_needed(struct sb *sb)
{
	if (current->journal_info)
		change_end(sb);
}
