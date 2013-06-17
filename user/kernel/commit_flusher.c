#if TUX3_FLUSHER != TUX3_FLUSHER_ASYNC_HACK
#include "tux3.h"

static void __tux3_init_flusher(struct sb *sb)
{
#ifdef __KERNEL__
	/* Disable writeback task to control inode reclaim by dirty flags */
	vfs_sb(sb)->s_bdi = &noop_backing_dev_info;
#endif
}

#if TUX3_FLUSHER == TUX3_FLUSHER_ASYNC_OWN
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

int tux3_init_flusher(struct sb *sb)
{
	struct task_struct *task;
	char b[BDEVNAME_SIZE];

	__tux3_init_flusher(sb);

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

static void schedule_flush_delta(struct sb *sb)
{
	/* Start the flusher for pending delta */
	wake_up_process(sb->flush_task);
}

#else /* TUX3_FLUSHER != TUX3_FLUSHER_ASYNC_OWN */

int tux3_init_flusher(struct sb *sb)
{
	__tux3_init_flusher(sb);
	return 0;
}

void tux3_exit_flusher(struct sb *sb)
{
}

static void schedule_flush_delta(struct sb *sb)
{
	/* Wake up waiters for pending marshal delta */
	wake_up_all(&sb->delta_event_wq);
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
#endif /* TUX3_FLUSHER != TUX3_FLUSHER_ASYNC_OWN */

/* Try delta transition */
static void try_delta_transition(struct sb *sb)
{
	trace("marshal %u, backend_state %lx",
	      sb->marshal_delta, sb->backend_state);
	if (!test_and_set_bit(TUX3_COMMIT_RUNNING_BIT, &sb->backend_state))
		delta_transition(sb);
}

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

#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	if (!delta_after_eq(sb->committed_delta, delta))
		flush_pending_delta(sb);
#endif

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

#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
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
#if TUX3_FLUSHER == TUX3_FLUSHER_SYNC
	up_write(&sb->delta_lock);
#endif

	return err;
}
#endif /* TUX3_FLUSHER == TUX3_FLUSHER_ASYNC_HACK */
