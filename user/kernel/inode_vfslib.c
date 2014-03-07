/*
 * Copied some vfs library functions to add change_{begin,end} and
 * tux3_iattrdirty().
 *
 * We should check the update of original functions, and sync with it.
 */

#include <linux/splice.h>
#include <linux/aio.h>		/* for kiocb */

/*
 * Almost copy of generic_file_aio_write() (added changed_begin/end,
 * tux3_iattrdirty()).
 */
static ssize_t tux3_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct sb *sb = tux_sb(inode->i_sb);
	ssize_t ret;

	BUG_ON(iocb->ki_pos != pos);

	mutex_lock(&inode->i_mutex);
	/* For each ->write_end() calls change_end(). */
	change_begin(sb);
	/* For timestamp. FIXME: convert this to ->update_time handler? */
	tux3_iattrdirty(inode);
	ret = __generic_file_aio_write(iocb, iov, nr_segs, &iocb->ki_pos);
	change_end_if_needed(sb);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0) {
		ssize_t err;

		err = generic_write_sync(file, iocb->ki_pos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

/*
 * Almost copy of generic_file_splice_write() (added changed_begin/end,
 * tux3_iattrdirty()).
 */
static ssize_t tux3_file_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	struct address_space *mapping = out->f_mapping;
	struct inode *inode = mapping->host;
	struct sb *sb = tux_sb(inode->i_sb);
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};
	ssize_t ret;

	pipe_lock(pipe);

	splice_from_pipe_begin(&sd);
	do {
		ret = splice_from_pipe_next(pipe, &sd);
		if (ret <= 0)
			break;

		mutex_lock_nested(&inode->i_mutex, I_MUTEX_CHILD);
		/* For each ->write_end() calls change_end(). */
		change_begin(sb);
		/* For timestamp. FIXME: convert this to ->update_time
		 * handler? */
		tux3_iattrdirty(inode);
		ret = file_remove_suid(out);
		if (!ret) {
			ret = file_update_time(out);
			if (!ret)
				ret = splice_from_pipe_feed(pipe, &sd,
							    pipe_to_file);
		}
		change_end_if_needed(sb);
		mutex_unlock(&inode->i_mutex);
	} while (ret > 0);
	splice_from_pipe_end(pipe, &sd);

	pipe_unlock(pipe);

	if (sd.num_spliced)
		ret = sd.num_spliced;

	if (ret > 0) {
		int err;

		err = generic_write_sync(out, *ppos, ret);
		if (err)
			ret = err;
		else
			*ppos += ret;
		balance_dirty_pages_ratelimited(mapping);
	}

	return ret;
}
