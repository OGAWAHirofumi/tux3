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

/* FIXME: maybe, we can share code more with inode.c and iattr.c. */
enum { ORPHAN_ATTR, };
static unsigned orphan_asize[] = {
	/* Fixed size attrs */
	[ORPHAN_ATTR] = 0,
};

static void *orphan_encode_attrs(struct inode *inode, void *attrs)
{
	return encode_kind(attrs, ORPHAN_ATTR, tux_sb(inode->i_sb)->version);
}

static int store_orphan_inum(struct inode *inode, struct cursor *cursor)
{
	unsigned size;
	void *base;

	size = orphan_asize[ORPHAN_ATTR] + 2;

	base = btree_expand(cursor, tux_inode(inode)->inum, size);
	if (IS_ERR(base))
		return PTR_ERR(base);

	orphan_encode_attrs(inode, base);
	mark_buffer_dirty_non(cursor_leafbuf(cursor));

	return 0;
}

/* Add inum into sb->otable */
int tux3_rollup_orphan_add(struct sb *sb, struct list_head *orphan_add)
{
	struct btree *otable = otable_btree(sb);
	struct cursor *cursor;
	int err = 0;

	if (list_empty(orphan_add))
		return 0;

	down_write(&otable->lock);
	if (!has_root(otable))
		err = alloc_empty_btree(otable);
	up_write(&otable->lock);
	if (err)
		return err;

	/* FIXME: +1 may not be enough to add multiple */
	cursor = alloc_cursor(otable, 1); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;

	down_write(&cursor->btree->lock);
	while (!list_empty(orphan_add)) {
		struct inode *inode;
		inode = list_entry(orphan_add->next, struct inode, orphan_list);

		/* FIXME: what to do if error? */
		err = btree_probe(cursor, inode->inum);
		if (err)
			goto out;

		err = store_orphan_inum(inode, cursor);
		release_cursor(cursor);
		if (err)
			goto out;

		list_del_init(&inode->orphan_list);
	}
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);

	return err;
}

/* Delete inum from sb->otable */
int tux3_rollup_orphan_del(struct inode *inode)
{
	struct btree *otable = otable_btree(tux_sb(inode->i_sb));
	return purge_inum(otable, tux_inode(inode)->inum);
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
