/*
 * Tux3 versioning filesystem inode operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 2
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"
#include "ileaf.h"

#ifndef trace
#define trace trace_on
#endif

static void tux_setup_inode(struct inode *inode);

static inline void tux_set_inum(struct inode *inode, inum_t inum)
{
#ifdef __KERNEL__
	inode->i_ino = inum;
#endif
	tux_inode(inode)->inum = inum;
}

struct inode *tux_new_volmap(struct sb *sb)
{
	struct inode *inode = new_inode(vfs_sb(sb));
	if (inode) {
		inode->i_size = (loff_t)sb->volblocks << sb->blockbits;
		tux_set_inum(inode, TUX_VOLMAP_INO);
		insert_inode_hash(inode);
		tux_setup_inode(inode);
	}
	return inode;
}

/* FIXME: kill this, and use another infrastructure instead of inode */
struct inode *tux_new_logmap(struct sb *sb)
{
	struct inode *inode = new_inode(vfs_sb(sb));
	if (inode) {
		tux_set_inum(inode, TUX_LOGMAP_INO);
		tux_setup_inode(inode);
	}
	return inode;
}

static struct inode *tux_new_inode(struct inode *dir, struct tux_iattr *iattr,
				   dev_t rdev)
{
	struct inode *inode;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return NULL;
	assert(!tux_inode(inode)->present);

	inode->i_mode = iattr->mode;
	inode->i_uid = iattr->uid;
	if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISGID;
	} else
		inode->i_gid = iattr->gid;
	inode->i_mtime = inode->i_ctime = inode->i_atime = gettime();
	switch (inode->i_mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR:
		/* vfs, trying to be helpful, will rewrite the field */
		inode->i_rdev = rdev;
		tux_inode(inode)->present |= RDEV_BIT;
		break;
	case S_IFDIR:
		inc_nlink(inode);
		break;
	}
	tux_inode(inode)->present |= CTIME_SIZE_BIT|MTIME_BIT|MODE_OWNER_BIT|DATA_BTREE_BIT|LINK_COUNT_BIT;

	/* Just for debug, will rewrite by alloc_inum() */
	tux_set_inum(inode, TUX_INVALID_INO);

	return inode;
}

/*
 * Deferred ileaf update for inode number allocation
 */
/* must hold itable->btree.lock */
static int is_defer_alloc_inum(struct inode *inode)
{
	return !list_empty(&tux_inode(inode)->alloc_list);
}

/* must hold itable->btree.lock */
static int find_defer_alloc_inum(struct sb *sb, inum_t inum)
{
	tuxnode_t *tuxnode;

	list_for_each_entry(tuxnode, &sb->alloc_inodes, alloc_list) {
		if (tuxnode->inum == inum)
			return 1;
	}
	return 0;
}

/* must hold itable->btree.lock */
static void add_defer_alloc_inum(struct inode *inode)
{
	/* FIXME: need to reserve space (ileaf/bnodes) for this inode? */
	struct sb *sb = tux_sb(inode->i_sb);
	list_add_tail(&tux_inode(inode)->alloc_list, &sb->alloc_inodes);
}

/* must hold itable->btree.lock. FIXME: spinlock is enough? */
void del_defer_alloc_inum(struct inode *inode)
{
	list_del_init(&tux_inode(inode)->alloc_list);
}

/*
 * Inode table expansion algorithm
 *
 * First probe for the inode goal.  This retreives the rightmost leaf that
 * contains an inode less than or equal to the goal.  (We could in theory avoid
 * retrieving any leaf at all in some cases if we observe that the the goal must
 * fall into an unallocated gap between two index keys, for what that is worth.
 * Probably not very much.)
 *
 * If not at end then next key is greater than goal.  This block has the highest
 * ibase less than or equal to goal.  Ibase should be equal to btree key, so
 * assert.  Search block even if ibase is way too low.  If goal comes back equal
 * to next_key then there is no room to create more inodes in it, so advance to
 * the next block and repeat.
 *
 * Otherwise, expand the inum goal that came back.  If ibase was too low to
 * create the inode in that block then the low level split will fail and expand
 * will create a new inode table block with ibase at the goal.  We round the
 * goal down to some binary multiple in ileaf_split to reduce the chance of
 * creating inode table blocks with only a small number of inodes.  (Actually
 * we should only round down the split point, not the returned goal.)
 */

static int find_free_inum(struct cursor *cursor, inum_t goal, inum_t *allocated)
{
	int ret;

#ifndef __KERNEL__ /* FIXME: kill this, only mkfs path needs this */
	/* If this is not mkfs path, it should have itable root */
	if (!has_root(cursor->btree)) {
		*allocated = goal;
		return 0;
	}
#endif

	ret = btree_probe(cursor, goal);
	if (ret)
		return ret;

	/* FIXME: need better allocation policy */

	/*
	 * Find free inum from goal, and wrapped to TUX_NORMAL_INO if
	 * not found. This prevent to use less than TUX_NORMAL_INO if
	 * reserved ino was not specified explicitly.
	 */
	ret = btree_traverse(cursor, goal, TUXKEY_LIMIT, ileaf_find_free,
			     allocated);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		/* Found free inum */
		ret = 0;
		goto out;
	}

	if (TUX_NORMAL_INO < goal) {
		u64 len = goal - TUX_NORMAL_INO;

		ret = btree_traverse(cursor, TUX_NORMAL_INO, len,
				     ileaf_find_free, allocated);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			/* Found free inum */
			ret = 0;
			goto out;
		}
	}

	/* Couldn't find free inum */
	ret = -ENOSPC;

out:
	release_cursor(cursor);

	return ret;
}

/*
 * Choose preferable inode number
 *
 * For now the inum allocation goal is the same as the block allocation
 * goal.  This allows a maximum inum density of one per block and should
 * give pretty good spacial correlation between inode table blocks and
 * file data belonging to those inodes provided somebody sets the block
 * allocation goal based on the directory the file will be in.
 *
 * FIXME: better allocation algorithm?
 */
static inum_t alloc_inum_goal(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	inum_t goal = sb->nextalloc;

	/* Don't choose reserved ino */
	if (goal < TUX_NORMAL_INO)
		goal = TUX_NORMAL_INO;
	return goal;
}

static int alloc_inum(struct inode *inode, inum_t goal)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *itable = itable_btree(sb);
	struct cursor *cursor;
	int err = 0;

	cursor = alloc_cursor(itable, 1); /* +1 for now depth */
	if (!cursor)
		return -ENOMEM;

	down_write(&cursor->btree->lock);
	while (1) {
		err = find_free_inum(cursor, goal, &goal);
		if (err)
			goto error;

		/* Is this inum already used by deferred inum allocation? */
		if (!find_defer_alloc_inum(sb, goal))
			break;

		goal++;
		while (find_defer_alloc_inum(sb, goal))
			goal++;
	}

	/* FIXME: should use conditional inode->present. But,
	 * btree->lock is needed to initialize. */
	if (tux_inode(inode)->present & DATA_BTREE_BIT)
		init_btree(&tux_inode(inode)->btree, sb, no_root, dtree_ops());

	/* Final initialization of inode */
	tux_set_inum(inode, goal);
	tux_setup_inode(inode);

	add_defer_alloc_inum(inode);

error:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);

	return err;
}

struct inode *__tux_create_inode(struct inode *dir, inum_t goal,
				 struct tux_iattr *iattr, dev_t rdev)
{
	struct inode *inode;

	inode = tux_new_inode(dir, iattr, rdev);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	int err = alloc_inum(inode, goal);
	if (err) {
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(err);
	}
	insert_inode_hash(inode);
	/*
	 * The unhashed inode ignores mark_inode_dirty(), so it should
	 * be called after insert_inode_hash().
	 */
	mark_inode_dirty(inode);

	return inode;
}

struct inode *tux_create_inode(struct inode *dir, struct tux_iattr *iattr,
			       dev_t rdev)
{
	return __tux_create_inode(dir, alloc_inum_goal(dir), iattr, rdev);
}

static int check_present(struct inode *inode)
{
	tuxnode_t *tuxnode = tux_inode(inode);

	switch (inode->i_mode & S_IFMT) {
	case S_IFSOCK:
	case S_IFIFO:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(!(tuxnode->present & RDEV_BIT));
		break;
	case S_IFBLK:
	case S_IFCHR:
		assert(tuxnode->present & MODE_OWNER_BIT);
//		assert(tuxnode->present & RDEV_BIT);
		break;
	case S_IFREG:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		assert(!(tuxnode->present & RDEV_BIT));
		break;
	case S_IFDIR:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		assert(!(tuxnode->present & RDEV_BIT));
		break;
	case S_IFLNK:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		assert(!(tuxnode->present & RDEV_BIT));
		break;
	case 0: /* internal inode */
		if (tux_inode(inode)->inum == TUX_VOLMAP_INO)
			assert(tuxnode->present == 0);
		else {
			assert(tuxnode->present & DATA_BTREE_BIT);
			assert(!(tuxnode->present & RDEV_BIT));
		}
		break;
	default:
		error("Unknown mode: inum %Lx, mode %07ho",
		      tuxnode->inum, inode->i_mode);
		break;
	}
	return 0;
}

static int open_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *itable = itable_btree(sb);
	int err;

	struct cursor *cursor = alloc_cursor(itable, 0);
	if (!cursor)
		return -ENOMEM;

	down_read(&cursor->btree->lock);
	if ((err = btree_probe(cursor, tux_inode(inode)->inum)))
		goto out;

	/* Read inode attribute from inode btree */
	struct ileaf_req rq = {
		.key = {
			.start	= tux_inode(inode)->inum,
			.len	= 1,
		},
		.data	= inode,
	};
	err = btree_read(cursor, &rq.key);
	if (err == -ENOENT)
		warn("inum %llx couldn't found", tux_inode(inode)->inum);
	if (!err) {
		check_present(inode);
		tux_setup_inode(inode);
	}

	release_cursor(cursor);
out:
	up_read(&cursor->btree->lock);
	free_cursor(cursor);

	return err;
}

static int tux_test(struct inode *inode, void *data)
{
	return tux_inode(inode)->inum == *(inum_t *)data;
}

static int tux_set(struct inode *inode, void *data)
{
	tux_set_inum(inode, *(inum_t *)data);
	return 0;
}

struct inode *tux3_iget(struct sb *sb, inum_t inum)
{
	struct inode *inode;
	int err;

	inode = iget5_locked(vfs_sb(sb), inum, tux_test, tux_set, &inum);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = open_inode(inode);
	if (err) {
		iget_failed(inode);
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);
	return inode;
}

static int save_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *itable = itable_btree(sb);
	inum_t inum = tux_inode(inode)->inum;
	int err = 0;

	assert(inum != TUX_LOGMAP_INO && inum != TUX_INVALID_INO);
	trace("save inode 0x%Lx", inum);

#ifndef __KERNEL__
	/* FIXME: kill this, only mkfs path needs this */
	/* FIXME: this should be merged to btree_expand()? */
	down_write(&itable->lock);
	if (!has_root(itable))
		err = alloc_empty_btree(itable);
	up_write(&itable->lock);
	if (err)
		return err;
#endif

	struct cursor *cursor = alloc_cursor(itable, 1); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;

	down_write(&cursor->btree->lock);
	if ((err = btree_probe(cursor, inum)))
		goto out;
	/* paranoia check */
	if (!is_defer_alloc_inum(inode)) {
		unsigned size;
		assert(ileaf_lookup(itable, inum, bufdata(cursor_leafbuf(cursor)), &size));
	}

	/* Write inode attributes to inode btree */
	struct ileaf_req rq = {
		.key = {
			.start	= inum,
			.len	= 1,
		},
		.data		= inode,
	};
	err = btree_write(cursor, &rq.key);
	if (err)
		goto error_release;

	del_defer_alloc_inum(inode);

error_release:
	release_cursor(cursor);
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
}

static int tux3_truncate_blocks(struct inode *inode, loff_t newsize)
{
	struct sb *sb = tux_sb(inode->i_sb);
	tuxkey_t index = (newsize + sb->blockmask) >> sb->blockbits;

	return btree_chop(&tux_inode(inode)->btree, index, TUXKEY_LIMIT);
}

#ifdef __KERNEL__
/* Truncate partial block. If partial, we have to update last block. */
static int tux3_truncate_partial_block(struct inode *inode, loff_t newsize)
{
	return block_truncate_page(inode->i_mapping, newsize, tux3_get_block);
}

void tux3_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, to, inode->i_size);
		tux3_truncate_blocks(inode, inode->i_size);
	}
}
#endif /* !__KERNEL__ */

static int tux3_truncate(struct inode *inode, loff_t newsize)
{
	/* FIXME: expanding size is not tested */
	struct sb *sb = tux_sb(inode->i_sb);
	int is_expand, err;

	if (newsize == inode->i_size)
		return 0;

	/* inode_dio_wait(inode); */	/* FIXME: for direct I/O */

	err = 0;
	is_expand = newsize > inode->i_size;

	change_begin(sb);

	if (!is_expand) {
		err = tux3_truncate_partial_block(inode, newsize);
		if (err)
			goto error;
	}

	/* Change i_size, then clean buffers */
	truncate_setsize(inode, newsize);

	if (!is_expand) {
		err = tux3_truncate_blocks(inode, newsize);
		if (err)
			goto error;
	}

	inode->i_mtime = inode->i_ctime = gettime();
	mark_inode_dirty(inode);
error:
	change_end(sb);

	return err;
}

/* Remove inode from itable */
static int purge_inode(struct inode *inode)
{
	struct btree *itable = itable_btree(tux_sb(inode->i_sb));

	down_write(&itable->lock);	/* FIXME: spinlock is enough? */
	if (is_defer_alloc_inum(inode)) {
		del_defer_alloc_inum(inode);
		up_write(&itable->lock);
		return 0;
	}
	up_write(&itable->lock);

	/* Remove inum from inode btree */
	return btree_chop(itable, tux_inode(inode)->inum, 1);
}

/*
 * In-core inode is going to be freed, do job for it.
 */
void tux3_evict_inode(struct inode *inode)
{
#ifdef __KERNEL__
	/* Block device special file is still overwriting i_mapping */
	truncate_inode_pages(&inode->i_data, 0);
#else
	truncate_inode_pages(mapping(inode), 0);
#endif

	if (inode->i_nlink > 0 || is_bad_inode(inode))
		end_writeback(inode);
	else {
		/*
		 * FIXME: since in-core inode is freed, we should do
		 * something for freeing inode even if error happened.
		 *
		 * truncate might take long time, we should do
		 * something to prevent it.
		 */
		struct sb *sb = tux_sb(inode->i_sb);
		int err;

		change_begin(sb);

		/*
		 * FIXME: i_blocks (if implemented) would be better way
		 * than inode->i_size to know whether we have to
		 * traverse btree. (Or another better info?)
		 *
		 * inode->i_size = 0;
		 * if (inode->i_blocks)
		 */
		if (inode->i_size) {
			inode->i_size = 0;
			err = tux3_truncate_blocks(inode, 0);
			if (err)
				goto error;
		}
		err = free_empty_btree(&tux_inode(inode)->btree);
		if (err)
			goto error;

		err = xcache_remove_all(inode);
		if (err)
			goto error;

		/*
		 * Orphan is cleared. We can't call change_end()
		 * anymore until inode was removed.
		 */
		err = tux3_clear_inode_orphan(inode);
		if (err)
			goto error;

		err = purge_inode(inode);
error:
		/*
		 * Clean inode (clear I_DIRTY) before change_end() to
		 * prevent to flush removed inode. (Since this is
		 * protected by change_begin/end(), there shouldn't be
		 * no writeback process for this inode)
		 */
		end_writeback(inode);

		change_end(sb);
	}

	free_xcache(inode);
}

#ifdef __KERNEL__
int tux3_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* Those inodes must not be marked as I_DIRTY_SYNC/DATASYNC. */
	BUG_ON(tux_inode(inode)->inum == TUX_BITMAP_INO ||
	       tux_inode(inode)->inum == TUX_VOLMAP_INO ||
	       tux_inode(inode)->inum == TUX_VTABLE_INO ||
	       tux_inode(inode)->inum == TUX_LOGMAP_INO ||
	       tux_inode(inode)->inum == TUX_INVALID_INO ||
	       tux_inode(inode)->inum == TUX_ATABLE_INO);
	/* this should not update the bitmap/vtable/atable except btree root */
	return save_inode(inode);
}

int tux3_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;

	generic_fillattr(inode, stat);
	stat->ino = tux_inode(inode)->inum;
	/*
	 * FIXME: need to implement ->i_blocks?
	 *
	 * If we want to add i_blocks account, we have to check
	 * existent extent for dirty buffer.  And only if there is no
	 * existent extent, we add to ->i_blocks.
	 *
	 * Yes, ->i_blocks must be including delayed allocation buffers
	 * as allocated, because some apps (e.g. tar) think it is empty file
	 * if i_blocks == 0.
	 *
	 * But, it is purely unnecessary overhead.
	 */
	stat->blocks = ALIGN(inode->i_size, sb->blocksize) >> 9;
	return 0;
}

int tux3_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int err;

	err = inode_change_ok(inode, iattr);
	if (err)
		return err;

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size) {
		inode_dio_wait(inode);

		err = tux3_truncate(inode, iattr->ia_size);
		if (err)
			return err;
	}

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	return 0;
}

static const struct file_operations tux_file_fops = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
//	.unlocked_ioctl	= fat_generic_ioctl,
#ifdef CONFIG_COMPAT
//	.compat_ioctl	= fat_compat_dir_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
//	.fsync		= file_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

static const struct inode_operations tux_file_iops = {
//	.permission	= ext4_permission,
	.setattr	= tux3_setattr,
	.getattr	= tux3_getattr
#ifdef CONFIG_EXT4DEV_FS_XATTR
//	.setxattr	= generic_setxattr,
//	.getxattr	= generic_getxattr,
//	.listxattr	= ext4_listxattr,
//	.removexattr	= generic_removexattr,
#endif
//	.fallocate	= ext4_fallocate,
//	.fiemap		= ext4_fiemap,
};

static const struct inode_operations tux_special_iops = {
//	.permission	= ext4_permission,
//	.setattr	= ext4_setattr,
	.getattr	= tux3_getattr
#ifdef CONFIG_EXT4DEV_FS_XATTR
//	.setxattr	= generic_setxattr,
//	.getxattr	= generic_getxattr,
//	.listxattr	= ext4_listxattr,
//	.removexattr	= generic_removexattr,
#endif
};

const struct inode_operations tux_symlink_iops = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= tux3_getattr,
#if 0
//	.setxattr	= generic_setxattr,
//	.getxattr	= generic_getxattr,
//	.listxattr	= ext4_listxattr,
//	.removexattr	= generic_removexattr,
#endif
};

static void tux_setup_inode(struct inode *inode)
{
	struct sb *sbi = tux_sb(inode->i_sb);

	assert(tux_inode(inode)->inum != TUX_INVALID_INO);

//	inode->i_generation = 0;
//	inode->i_flags = 0;

	switch (inode->i_mode & S_IFMT) {
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFBLK:
	case S_IFCHR:
		inode->i_op = &tux_special_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	case S_IFREG:
		inode->i_op = &tux_file_iops;
		inode->i_fop = &tux_file_fops;
		inode->i_mapping->a_ops = &tux_aops;
		break;
	case S_IFDIR:
		inode->i_op = &tux_dir_iops;
		inode->i_fop = &tux_dir_fops;
		inode->i_mapping->a_ops = &tux_blk_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
		break;
	case S_IFLNK:
		inode->i_op = &tux_symlink_iops;
		inode->i_mapping->a_ops = &tux_aops;
		break;
	case 0: /* internal inode */
	{
		inum_t inum = tux_inode(inode)->inum;
		gfp_t gfp_mask = GFP_USER;

		/* FIXME: bitmap, logmap, vtable, atable doesn't have S_IFMT */
		if (inum == TUX_VOLMAP_INO)
			inode->i_mapping->a_ops = &tux_vol_aops;
		else {
			/* set fake i_size to escape the check of block_* */
			inode->i_size = MAX_LFS_FILESIZE;
			inode->i_mapping->a_ops = &tux_blk_aops;
		}

		/* Prevent reentering into our fs recursively by mem reclaim */
		switch (inum) {
		case TUX_VOLMAP_INO:
		case TUX_BITMAP_INO:
		case TUX_LOGMAP_INO:
			gfp_mask &= ~__GFP_FS;
			break;
		}
		mapping_set_gfp_mask(inode->i_mapping, gfp_mask);
		break;
	}
	default:
		error("Unknown mode: inum %Lx, mode %07ho",
		      tux_inode(inode)->inum, inode->i_mode);
		break;
	}
}
#endif /* !__KERNEL__ */
