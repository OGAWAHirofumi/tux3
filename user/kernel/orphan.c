/*
 * Orphan inode management
 *
 * LOG_ORPHAN_ADD and LOG_ORPHAN_DEL are log records of frontend
 * operation for orphan state. With it, we don't need any write to FS
 * except log blocks. If the orphan is short life, it will be handled
 * by this.
 *
 * However, if the orphan is long life, it can make log blocks too long.
 * So, to prevent it, if orphan inodes are still living until rollup, we
 * store those inum into sb->otable. With it, we can obsolete log blocks.
 *
 * On replay, we can know the inum of orphan inodes yet not destroyed by
 * checking sb->otable, LOG_ORPHAN_ADD, and LOG_ORPHAN_DEL. (Note, orphan
 * inum of LOG_ORPHAN_ADD can be destroyed by same inum of LOG_ORPHAN_DEL).
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

int tux3_rollup_orphan_add(struct inode *inode)
{
	list_del_init(&inode->orphan_list);
	return 0;
}

int tux3_rollup_orphan_del(struct inode *inode)
{
	return 0;
}

/*
 * FIXME: Caching the frontend modification by sb->orphan_{add,del}
 * list. This is similar to sb->alloc_list of defered inum
 * allocation. Can't we make infrastructure to do this?
 */

/*
 * Mark inode as orphan, and logging it. Then if orphan is living until
 * rollup, orphan will be written to sb->otable.
 */
int tux3_mark_inode_orphan(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	assert(list_empty(&inode->orphan_list));
	list_add(&inode->orphan_list, &sb->orphan_add);
	log_orphan_add(sb, sb->version, inode->inum);

	return 0;
}

/* Clear inode as orphan (inode was destroyed), and logging it. */
int tux3_clear_inode_orphan(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	int err = 0;

	if (!list_empty(&inode->orphan_list)) {
		/* This orphan is not applied to sb->otable yet. */
		list_del_init(&inode->orphan_list);
		log_orphan_del(sb, sb->version, inode->inum);
	} else {
		/* This orphan was applied to sb->otable. */
		err = tux3_rollup_orphan_del(inode);
	}

	return err;
}
