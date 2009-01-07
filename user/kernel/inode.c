/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

static int check_present(struct inode *inode)
{
	tuxnode_t *tuxnode = tux_inode(inode);
	switch (inode->i_mode & S_IFMT) {
	default:
		assert(tuxnode->present & MODE_OWNER_BIT);
		/* FIXME: assert(!(tuxnode->present & RDEV_BIT)) */
		break;
	case S_IFBLK:
	case S_IFCHR:
		assert(tuxnode->present & MODE_OWNER_BIT);
		/* FIXME: assert(tuxnode->present & RDEV_BIT) */
		break;
	case S_IFREG:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		/* FIXME: assert(!(tuxnode->present & RDEV_BIT)) */
		break;
	case S_IFDIR:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		/* FIXME: assert(!(tuxnode->present & RDEV_BIT)) */
		break;
	case S_IFLNK:
		assert(tuxnode->present & MODE_OWNER_BIT);
		assert(tuxnode->present & DATA_BTREE_BIT);
		/* FIXME: assert(!(tuxnode->present & RDEV_BIT)) */
		break;
	case 0:
		assert(tuxnode->present & DATA_BTREE_BIT);
		/* FIXME: assert(!(tuxnode->present & RDEV_BIT)) */
		break;
	}
	return 0;
}

static inline void tux_set_inum(struct inode *inode, inum_t inum)
{
#ifdef __KERNEL__
	inode->i_ino = inum;
#endif
	tux_inode(inode)->inum = inum;
}

#ifdef __KERNEL__
static void tux_setup_inode(struct inode *inode, dev_t rdev);
#else
static void tux_setup_inode(struct inode *inode, dev_t rdev)
{
	inode->i_rdev = rdev;
}
#endif

struct inode *tux_new_inode(struct inode *dir, struct tux_iattr *iattr,
			    dev_t rdev)
{
	struct inode *inode = new_inode(dir->i_sb);
	if (!inode)
		return NULL;

	inode->i_mode = iattr->mode;
	inode->i_uid = iattr->uid;
	if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISGID;
	} else
		inode->i_gid = iattr->gid;
	inode->i_mtime = inode->i_ctime = inode->i_atime = gettime();
	if (S_ISDIR(inode->i_mode))
		inode->i_nlink++;
	tux_set_inum(inode, TUX_INVALID_INO);
	tux_inode(inode)->present = CTIME_SIZE_BIT|MTIME_BIT|MODE_OWNER_BIT|DATA_BTREE_BIT|LINK_COUNT_BIT;
	tux_setup_inode(inode, rdev);
	return inode;
}

static int open_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	int err;
	struct cursor *cursor = alloc_cursor(&sb->itable, 0);
	if (!cursor)
		return -ENOMEM;
	down_read(&cursor->btree->lock);
	if ((err = probe(&sb->itable, tux_inode(inode)->inum, cursor)))
		goto out;
	unsigned size;
	void *attrs = ileaf_lookup(&sb->itable, tux_inode(inode)->inum, bufdata(cursor_leafbuf(cursor)), &size);
	if (!attrs) {
		err = -ENOENT;
		goto release;
	}
	trace("found inode 0x%Lx", (L)tux_inode(inode)->inum);
	//ileaf_dump(&sb->itable, bufdata(cursor[depth].buffer));
	//hexdump(attrs, size);
	unsigned xsize = decode_xsize(inode, attrs, size);
	err = -ENOMEM;
	if (xsize && !(tux_inode(inode)->xcache = new_xcache(xsize)))
		goto release;
	decode_attrs(inode, attrs, size); // error???
	dump_attrs(inode);
	if (tux_inode(inode)->xcache)
		xcache_dump(inode);
	check_present(inode);
	tux_setup_inode(inode, inode->i_rdev);
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
	unsigned size = encode_asize(tux_inode(inode)->present) + encode_xsize(inode);
	void *base = tree_expand(&tux_sb(inode->i_sb)->itable, tux_inode(inode)->inum, size, cursor);
	if (!base)
		return -ENOMEM; // ERR_PTR me!!!
	void *attr = encode_attrs(inode, base, size);
	attr = encode_xattrs(inode, attr, base + size - attr);
	assert(attr == base + size);
	mark_buffer_dirty(cursor_leafbuf(cursor));
	return 0;
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

static int make_inode(struct inode *inode, inum_t goal)
{
	struct sb *sb = tux_sb(inode->i_sb);
	int err = -ENOENT, depth = sb->itable.root.depth;
	struct cursor *cursor = alloc_cursor(&sb->itable, 1); /* +1 for now depth */
	if (!cursor)
		return -ENOMEM;
	down_write(&cursor->btree->lock);
	if ((err = probe(&sb->itable, goal, cursor)))
		goto out;
	struct buffer_head *leafbuf = cursor_leafbuf(cursor);

	/* FIXME: inum allocation should check min and max */
	trace("create inode 0x%Lx", (L)goal);
	assert(!tux_inode(inode)->btree.root.depth);
	assert(goal < next_key(cursor, depth));
	while (1) {
		trace_off("find empty inode in [%Lx] base %Lx", (L)bufindex(leafbuf), (L)ibase(leaf));
		goal = find_empty_inode(&sb->itable, bufdata(leafbuf), goal);
		trace("result inum is %Lx, limit is %Lx", (L)goal, (L)next_key(cursor, depth));
		if (goal < next_key(cursor, depth))
			break;
		int more = advance(&sb->itable, cursor);
		if (more < 0) {
			err = more;
			goto out;
		}
		trace("no more inode space here, advance %i", more);
		if (!more) {
			err = -ENOSPC;
			goto release;
		}
	}

	tux_set_inum(inode, goal);
	if (tux_inode(inode)->present & DATA_BTREE_BIT)
		if ((err = new_btree(&tux_inode(inode)->btree, sb, &dtree_ops)))
			goto release;
	if ((err = store_attrs(inode, cursor)))
		goto out;
release:
	release_cursor(cursor);
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
}

static int save_inode(struct inode *inode)
{
	assert(tux_inode(inode)->inum != TUX_INVALID_INO);
	trace("save inode 0x%Lx", (L)tux_inode(inode)->inum);
	struct sb *sb = tux_sb(inode->i_sb);
	int err;
	struct cursor *cursor = alloc_cursor(&sb->itable, 1); /* +1 for new depth */
	if (!cursor)
		return -ENOMEM;
	down_write(&cursor->btree->lock);
	if ((err = probe(&sb->itable, tux_inode(inode)->inum, cursor)))
		goto out;
	/* paranoia check */
	unsigned size;
	if (!(ileaf_lookup(&sb->itable, tux_inode(inode)->inum, bufdata(cursor_leafbuf(cursor)), &size))) {
		err = -EINVAL;
		goto release;
	}
	if ((err = store_attrs(inode, cursor)))
		goto out;
release:
	release_cursor(cursor);
out:
	up_write(&cursor->btree->lock);
	free_cursor(cursor);
	return err;
}

static int purge_inum(struct btree *btree, inum_t inum)
{
	struct cursor *cursor = alloc_cursor(btree, 0);
	if (!cursor)
		return -ENOMEM;

	int err = -ENOENT;
	if (!(err = probe(btree, inum, cursor))) {
		/* FIXME: truncate the bnode and leaf if empty. */
		struct buffer_head *ileafbuf = cursor_leafbuf(cursor);
		struct ileaf *ileaf = to_ileaf(bufdata(ileafbuf));
		err = ileaf_purge(btree, inum, ileaf);
		if (!err)
			mark_buffer_dirty(ileafbuf);
		release_cursor(cursor);
	}
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

static void tux3_truncate(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct delete_info del_info = {
		.key = (inode->i_size + sb->blockmask) >> sb->blockbits,
	};
	int err;

	if (!tux_can_truncate(inode))
		return;
	/* FIXME: must fix expand size */
	WARN_ON(inode->i_size);
	block_truncate_page(inode->i_mapping, inode->i_size, tux3_get_block);
	change_begin(sb);
	err = tree_chop(&tux_inode(inode)->btree, &del_info, 0);
	inode->i_blocks = ((inode->i_size + sb->blockmask)
			   & ~(loff_t)sb->blockmask) >> 9;
	inode->i_mtime = inode->i_ctime = gettime();
	mark_inode_dirty(inode);
	change_end(sb);
}

void tux3_delete_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	inum_t inum = tux_inode(inode)->inum;

	change_begin(sb);
	truncate_inode_pages(&inode->i_data, 0);
	if (is_bad_inode(inode)) {
		clear_inode(inode);
		change_end(sb);
		return;
	}
	inode->i_size = 0;
	if (inode->i_blocks)
		tux3_truncate(inode);
	/* FIXME: we have to free dtree-root, atable entry, etc too */

	/* clear_inode() before freeing this ino. */
	clear_inode(inode);
	purge_inum(&sb->itable, inum);
	change_end(sb);
}

void tux3_clear_inode(struct inode *inode)
{
	if (tux_inode(inode)->xcache)
		kfree(tux_inode(inode)->xcache);
}

int tux3_write_inode(struct inode *inode, int do_sync)
{
	BUG_ON(tux_inode(inode)->inum == TUX_BITMAP_INO ||
	       tux_inode(inode)->inum == TUX_INVALID_INO ||
	       tux_inode(inode)->inum == TUX_VTABLE_INO ||
	       tux_inode(inode)->inum == TUX_ATABLE_INO);
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

static void tux_setup_inode(struct inode *inode, dev_t rdev)
{
	struct sb *sbi = tux_sb(inode->i_sb);

	inode->i_blocks = ((inode->i_size + sbi->blockmask)
			   & ~(loff_t)sbi->blockmask) >> 9;
//	inode->i_generation = 0;
//	inode->i_flags = 0;

	switch (inode->i_mode & S_IFMT) {
	default:
		inode->i_op = &tux_special_iops;
		init_special_inode(inode, inode->i_mode, rdev);
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
//		mapping_set_gfp_mask(inode->i_mapping, GFP_USER_PAGECACHE);
		mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
		break;
	case S_IFLNK:
		inode->i_op = &tux_symlink_iops;
		inode->i_mapping->a_ops = &tux_aops;
		break;
	case 0:
		/* FIXME: bitmap, logmap, vtable, atable doesn't have S_IFMT */
		/* set fake i_size to escape the check of read/writepage */
		inode->i_size = MAX_LFS_FILESIZE;
		inode->i_mapping->a_ops = &tux_blk_aops;
//		mapping_set_gfp_mask(inode->i_mapping, GFP_USER_PAGECACHE);
		mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
		break;
	}
}

struct inode *tux_create_inode(struct inode *dir, int mode, dev_t rdev)
{
	struct tux_iattr iattr = {
		.uid	= current->fsuid,
		.gid	= current->fsgid,
		.mode	= mode,
	};
	struct inode *inode = tux_new_inode(dir, &iattr, rdev);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	int err = make_inode(inode, tux_sb(dir->i_sb)->nextalloc);
	if (err) {
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(err);
	}
	insert_inode_hash(inode);
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
