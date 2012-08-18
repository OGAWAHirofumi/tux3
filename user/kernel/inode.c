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
		inode->i_nlink++;
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

static int alloc_inum(struct inode *inode, inum_t goal)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *itable = itable_btree(sb);
	int err = 0, depth = itable->root.depth;
	struct cursor *cursor;

	cursor = alloc_cursor(itable, 1); /* +1 for now depth */
	if (!cursor)
		return -ENOMEM;

	down_write(&cursor->btree->lock);
retry:
#ifndef __KERNEL__ /* FIXME: kill this, only mkfs path needs this */
	/* If this is not mkfs path, it should have itable root */
	if (!has_root(itable))
		goto skip_itable;
#endif
	if ((err = btree_probe(cursor, goal)))
		goto out;

	/* FIXME: inum allocation should check min and max */
	trace("create inode 0x%Lx", (L)goal);
	assert(!tux_inode(inode)->btree.root.depth);
	assert(goal < next_key(cursor, depth));
	while (1) {
		trace_off("find empty inode in [%Lx] base %Lx", (L)bufindex(cursor_leafbuf(cursor)), (L)ibase(leaf));
		goal = find_empty_inode(itable, bufdata(cursor_leafbuf(cursor)), goal);
		trace("result inum is %Lx, limit is %Lx", (L)goal, (L)next_key(cursor, depth));
		if (goal < next_key(cursor, depth))
			break;
		int more = cursor_advance(cursor);
		if (more < 0) {
			err = more;
			goto release;
		}
		trace("no more inode space here, advance %i", more);
		if (!more) {
			err = -ENOSPC;
			goto release;
		}
	}
#ifndef __KERNEL__ /* FIXME: kill this, only mkfs path needs this */
skip_itable:
#endif
	/* Is this inum already used by deferred inum allocation? */
	if (find_defer_alloc_inum(sb, goal)) {
		goal++;
		while (find_defer_alloc_inum(sb, goal))
			goal++;
		release_cursor(cursor);
		goto retry;
	}

	/* FIXME: should use conditional inode->present. But,
	 * btree->lock is needed to initialize. */
	if (tux_inode(inode)->present & DATA_BTREE_BIT)
		init_btree(&tux_inode(inode)->btree, sb, no_root, &dtree_ops);

	/* Final initialization of inode */
	tux_set_inum(inode, goal);
	tux_setup_inode(inode);

	add_defer_alloc_inum(inode);

release:
	release_cursor(cursor);
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
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
		error("Unknown mode: inum %Lx, mode %07o",
		      (L)tuxnode->inum, inode->i_mode);
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
	unsigned size;
	void *attrs = ileaf_lookup(itable, tux_inode(inode)->inum, bufdata(cursor_leafbuf(cursor)), &size);
	if (!attrs) {
		err = -ENOENT;
		goto release;
	}
	trace("found inode 0x%Lx", (L)tux_inode(inode)->inum);
	//ileaf_dump(itable, bufdata(cursor[depth].buffer));
	//hexdump(attrs, size);
	unsigned xsize = decode_xsize(inode, attrs, size);
	err = -ENOMEM;
	if (xsize && !(tux_inode(inode)->xcache = new_xcache(xsize)))
		goto release;
	decode_attrs(inode, attrs, size); // error???
	if (tux3_trace)
		dump_attrs(inode);
	if (tux_inode(inode)->xcache)
		xcache_dump(inode);
	check_present(inode);
	tux_setup_inode(inode);
	err = 0;
release:
	release_cursor(cursor);
out:
	up_read(&cursor->btree->lock);
	free_cursor(cursor);

	return err;
}

static int store_attrs(struct inode *inode, struct cursor *cursor)
{
	unsigned size;
	void *base;

	size = encode_asize(tux_inode(inode)->present) + encode_xsize(inode);
	assert(size);

	base = btree_expand(cursor, tux_inode(inode)->inum, size);
	if (IS_ERR(base))
		return PTR_ERR(base);

	void *attr = encode_attrs(inode, base, size);
	attr = encode_xattrs(inode, attr, base + size - attr);
	assert(attr == base + size);

	mark_buffer_dirty_non(cursor_leafbuf(cursor));

	return 0;
}

static int save_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree *itable = itable_btree(sb);
	inum_t inum = tux_inode(inode)->inum;
	int err = 0;

	assert(inum != TUX_LOGMAP_INO && inum != TUX_INVALID_INO);
	trace("save inode 0x%Lx", (L)inum);

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
	if ((err = store_attrs(inode, cursor)))
		goto error_release;
	del_defer_alloc_inum(inode);
error_release:
	release_cursor(cursor);
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
}

/*
 * NOTE: clear_inode() for this inode is already done. This shouldn't
 * use generic part of inode basically.
 */
static int purge_inum(struct inode *inode)
{
	struct btree *itable = itable_btree(tux_sb(inode->i_sb));

	down_write(&itable->lock);	/* FIXME: spinlock is enough? */
	if (is_defer_alloc_inum(inode)) {
		del_defer_alloc_inum(inode);
		up_write(&itable->lock);
		return 0;
	}
	up_write(&itable->lock);

	struct cursor *cursor = alloc_cursor(itable, 0);
	if (!cursor)
		return -ENOMEM;

	inum_t inum = tux_inode(inode)->inum;
	int err;
	down_write(&cursor->btree->lock);
	if (!(err = btree_probe(cursor, inum))) {
		if (!(err = cursor_redirect(cursor))) {
			/* FIXME: truncate the bnode and leaf if empty. */
			struct ileaf *ileaf = to_ileaf(bufdata(cursor_leafbuf(cursor)));
			ileaf_purge(itable, inum, ileaf);
			mark_buffer_dirty_non(cursor_leafbuf(cursor));
		}
		release_cursor(cursor);
	}
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
}

#ifdef __KERNEL__
static int tux_can_truncate(struct inode *inode)
{
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return 0;
	if (S_ISREG(inode->i_mode))
		return 1;
	if (S_ISDIR(inode->i_mode))
		return 1;
	if (S_ISLNK(inode->i_mode))
		return 1;
	return 0;
}

static void __tux3_truncate(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct btree_chop_info chop_info = {
		.key = (inode->i_size + sb->blockmask) >> sb->blockbits,
	};
	int err;

	if (!tux_can_truncate(inode))
		return;
	/* FIXME: must fix expand size */
	WARN_ON(inode->i_size);
	block_truncate_page(inode->i_mapping, inode->i_size, tux3_get_block);
	err = btree_chop(&tux_inode(inode)->btree, &del_info, 0);
	inode->i_blocks = ((inode->i_size + sb->blockmask)
			   & ~(loff_t)sb->blockmask) >> 9;
	inode->i_mtime = inode->i_ctime = gettime();
	mark_inode_dirty(inode);
}

static void tux3_truncate(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	change_begin(sb);
	__tux3_truncate(inode);
	change_end(sb);
}

void tux3_delete_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	change_begin(sb);
	truncate_inode_pages(&inode->i_data, 0);
	if (is_bad_inode(inode)) {
		clear_inode(inode);
		change_end(sb);
		return;
	}
	inode->i_size = 0;
	if (inode->i_blocks)
		__tux3_truncate(inode);
	/* FIXME: we have to free dtree-root, atable entry, etc too */
	free_empty_btree(&tux_inode(inode)->btree);

	/* clear_inode() before freeing this ino. */
	clear_inode(inode);
	purge_inum(inode);
	change_end(sb);
}

void tux3_clear_inode(struct inode *inode)
{
	if (tux_inode(inode)->xcache)
		kfree(tux_inode(inode)->xcache);
}

int tux3_write_inode(struct inode *inode, int do_sync)
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
	return 0;
}

int tux3_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int err;

	err = inode_change_ok(inode, iattr);
	if (err)
		return err;
	return inode_setattr(inode, iattr);
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
	.truncate	= tux3_truncate,
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

	inode->i_blocks = ((inode->i_size + sbi->blockmask)
			   & ~(loff_t)sbi->blockmask) >> 9;
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
		/* FIXME: kill this, this means logmap for now */
		case TUX_LOGMAP_INO:
			gfp_mask &= ~__GFP_FS;
			break;
		}
		mapping_set_gfp_mask(inode->i_mapping, gfp_mask);
		break;
	}
	default:
		error("Unknown mode: inum %Lx, mode %07o",
		      (L)tux_inode(inode)->inum, inode->i_mode);
		break;
	}
}

struct inode *tux_create_inode(struct inode *dir, int mode, dev_t rdev)
{
	struct tux_iattr iattr = {
		.uid	= current_fsuid(),
		.gid	= current_fsgid(),
		.mode	= mode,
	};
	struct inode *inode;

	inode = tux_new_inode(dir, &iattr, rdev);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	int err = alloc_inum(inode, tux_sb(dir->i_sb)->nextalloc);
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

static int tux_test(struct inode *inode, void *data)
{
	return tux_inode(inode)->inum == *(inum_t *)data;
}

static int tux_set(struct inode *inode, void *data)
{
	tux_set_inum(inode, *(inum_t *)data);
	return 0;
}

struct inode *tux3_iget(struct super_block *sb, inum_t inum)
{
	struct inode *inode;
	int err;

	inode = iget5_locked(sb, inum, tux_test, tux_set, &inum);
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
#endif /* !__KERNEL__ */
