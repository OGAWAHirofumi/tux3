#if TUX3_FLUSHER == TUX3_FLUSHER_ASYNC_HACK
#include "tux3.h"
#include <linux/kthread.h>
#include <linux/freezer.h>

/*
 * HACK: We set BDI_CAP_NO_WRITEBACK to bdi to disable flusher task
 * management to overwrite flusher task.
 *
 * But, BDI_CAP_NO_WRITEBACK disables also some functionality. So, we
 * replace some check by own check.
 *
 * FIXME: Remove this file after implement of flusher interface
 */

void tux3_accout_set_writeback(struct page *page)
{
	/*
	 * Hack: BDI_CAP_NO_WRITEBACK disables this accouting, so we
	 * do ourself instead.
	 */
	struct address_space *mapping = page->mapping;
	if (mapping)
		inc_bdi_stat(mapping->backing_dev_info, BDI_WRITEBACK);
}

void tux3_accout_clear_writeback(struct page *page)
{
	/*
	 * Hack: BDI_CAP_NO_WRITEBACK disables this accouting, so we
	 * do ourself instead.
	 */
	struct address_space *mapping = page->mapping;
	if (mapping) {
		dec_bdi_stat(mapping->backing_dev_info, BDI_WRITEBACK);
		bdi_writeout_inc(mapping->backing_dev_info);
	}
}

void tux3_set_mapping_bdi(struct inode *inode)
{
	/*
	 * Hack: set backing_dev_info to overwrite flusher task.
	 */
	inode->i_mapping->backing_dev_info = inode->i_sb->s_bdi;
}

/*
 * If dirty inode list was empty, we start the timer for periodical
 * flush.  (based on bdi_wakeup_thread_delayed())
 *
 * Hack: BDI_CAP_NO_WRITEBACK disables to wakeup flusher. So, we do
 * ourself instead.
 */
void tux3_start_periodical_flusher(struct sb *sb)
{
	struct backing_dev_info *bdi = vfs_sb(sb)->s_bdi;
	unsigned long timeout;

	timeout = msecs_to_jiffies(dirty_writeback_interval * 10);
	mod_timer(&bdi->wb.wakeup_timer, jiffies + timeout);
}

/*
 * FIXME: dirty hack for now. We should add callback in writeback task
 * instead of custom bdi.
 */
struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	unsigned long *older_than_this;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	enum wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct completion *done;	/* set if the caller waits */
};

static struct wb_writeback_work *
get_next_work_item(struct backing_dev_info *bdi)
{
	struct wb_writeback_work *work = NULL;

	spin_lock_bh(&bdi->wb_lock);
	if (!list_empty(&bdi->work_list)) {
		work = list_entry(bdi->work_list.next,
				  struct wb_writeback_work, list);
		list_del_init(&work->list);
	}
	spin_unlock_bh(&bdi->wb_lock);
	return work;
}

static long tux3_do_writeback(struct bdi_writeback *wb, int force_wait)
{
	struct backing_dev_info *bdi = wb->bdi;
	struct wb_writeback_work *work = NULL;
	long wrote = 0;

	set_bit(BDI_writeback_running, &wb->bdi->state);
	while ((work = get_next_work_item(bdi)) != NULL) {
		trace("nr_pages %ld, sb %p, sync_mode %d, "
		      "tagged_writepages %d, for_kupdate %d, range_cyclic %d, "
		      "for_background %d, reason %d, done %p",
		      work->nr_pages, work->sb, work->sync_mode,
		      work->tagged_writepages, work->for_kupdate,
		      work->range_cyclic, work->for_background,
		      work->reason, work->done);

		/*
		 * Override sync mode, in case we must wait for completion
		 * because this thread is exiting now.
		 */
		if (force_wait)
			work->sync_mode = WB_SYNC_ALL;
#if 0
		wrote += wb_writeback(wb, work);
#endif
		/*
		 * Notify the caller of completion if this is a synchronous
		 * work item, otherwise just free it.
		 */
		if (work->done)
			complete(work->done);
		else
			kfree(work);
	}
	trace("flush done");
#if 0
	/*
	 * Check for periodic writeback, kupdated() style
	 */
	wrote += wb_check_old_data_flush(wb);
	wrote += wb_check_background_flush(wb);
#endif
	clear_bit(BDI_writeback_running, &wb->bdi->state);

	return wrote;
}

/*
 * Handle writeback of dirty data for the device backed by this bdi. Also
 * wakes up periodically and does kupdated style flushing.
 */
static int tux3_writeback_thread(void *data)
{
	struct bdi_writeback *wb = data;
	struct backing_dev_info *bdi = wb->bdi;
	long pages_written;

	current->flags |= PF_SWAPWRITE;
	set_freezable();
	wb->last_active = jiffies;

	/*
	 * Our parent may run at a different priority, just set us to normal
	 */
	set_user_nice(current, 0);

	while (!kthread_freezable_should_stop(NULL)) {
		/*
		 * Remove own delayed wake-up timer, since we are already awake
		 * and we'll take care of the preriodic write-back.
		 */
		del_timer(&wb->wakeup_timer);
#if 0
		{
			struct inode *inode;
			spin_lock(&wb->list_lock);
			list_for_each_entry(inode, &wb->b_dirty, i_wb_list) {
				trace("inum %Lx", tux_inode(inode)->inum);
			}
			spin_unlock(&wb->list_lock);
		}
#endif
		pages_written = tux3_do_writeback(wb, 0);

		if (pages_written)
			wb->last_active = jiffies;

		set_current_state(TASK_INTERRUPTIBLE);
		if (!list_empty(&bdi->work_list) || kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			continue;
		}

		if (wb_has_dirty_io(wb) && dirty_writeback_interval)
			schedule_timeout(msecs_to_jiffies(dirty_writeback_interval * 10));
		else {
			/*
			 * We have nothing to do, so can go sleep without any
			 * timeout and save power. When a work is queued or
			 * something is made dirty - we will be woken up.
			 */
			schedule();
		}
	}

	/* Flush any work that raced with us exiting */
	if (!list_empty(&bdi->work_list))
		tux3_do_writeback(wb, 1);

	return 0;
}

static int tux3_congested_fn(void *congested_data, int bdi_bits)
{
	return bdi_congested(congested_data, bdi_bits);
}

/*
 * We need to disable writeback to control dirty flags of inode.
 * Otherwise, writeback will clear dirty, and inode can be reclaimed
 * without our control.
 */
int tux3_setup_flusher(struct sb *sb)
{
	struct backing_dev_info *bdi = &sb->bdi;
	dev_t dev = vfs_sb(sb)->s_bdev->bd_dev;
	struct task_struct *task;
	int err;

	bdi->ra_pages		= vfs_sb(sb)->s_bdi->ra_pages;
	bdi->congested_fn	= tux3_congested_fn;
	bdi->congested_data	= vfs_sb(sb)->s_bdi;

	err = bdi_setup_and_register(bdi, "tux3",
				     BDI_CAP_NO_WRITEBACK | BDI_CAP_MAP_COPY);
	if (err)
		return err;

	task = kthread_create(tux3_writeback_thread, &bdi->wb,
			      "flush-%s-%u:%u",
			      bdi->name, MAJOR(dev), MINOR(dev));
	if (IS_ERR(task)) {
		bdi_destroy(bdi);
		return PTR_ERR(task);
	}

	/*
	 * The spinlock makes sure we do not lose wake-ups when racing
	 * with 'bdi_queue_work()'.  And as soon as the bdi thread is
	 * visible, we can start it.
	 */
	spin_lock_bh(&bdi->wb_lock);
	bdi->wb.task = task;
	spin_unlock_bh(&bdi->wb_lock);

	vfs_sb(sb)->s_bdi = bdi;

	wake_up_process(task);

	return 0;
}

void tux3_cleanup_flusher(struct sb *sb)
{
	struct backing_dev_info *bdi = vfs_sb(sb)->s_bdi;

	/*
	 * If bdi has BDI_CAP_NO_WRITEBACK, bdi_destory() doesn't
	 * cleanup bdi. So, this remove it from capabilities.
	 */
	bdi->capabilities &= ~BDI_CAP_NO_WRITEBACK;
	bdi_destroy(bdi);
}
#endif /* TUX3_FLUSHER != TUX3_FLUSHER_ASYNC_HACK */
