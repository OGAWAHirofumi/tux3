/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include "tux3.h"

static void __tux3_put_super(struct sb *sbi)
{
	destroy_defer_bfree(&sbi->derollup);
	destroy_defer_bfree(&sbi->defree);

	iput(sbi->rootdir);
	sbi->rootdir = NULL;
	iput(sbi->atable);
	sbi->atable = NULL;
	iput(sbi->vtable);
	sbi->vtable = NULL;
	iput(sbi->bitmap);
	sbi->bitmap = NULL;
	iput(sbi->logmap);
	sbi->logmap = NULL;
	iput(sbi->volmap);
	sbi->volmap = NULL;

	/* FIXME: add more sanity check */
	assert(list_empty(&sbi->alloc_inodes));
}

struct replay *tux3_init_fs(struct sb *sbi)
{
	struct replay *rp = NULL;
	struct inode *inode;
	int err;

	err = -ENOMEM;

	/* Prepare non on-disk inodes */
	sbi->volmap = tux_new_volmap(sbi);
	if (!sbi->volmap)
		goto error;

	sbi->logmap = tux_new_logmap(sbi);
	if (!sbi->logmap)
		goto error;

	/* Replay physical structures */
	rp = replay_stage1(sbi);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}

	/* Load internal inodes */
	inode = iget_or_create_inode(sbi, TUX_BITMAP_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->bitmap = inode;
#if 0
	inode = tux3_iget(sbi, TUX_VTABLE_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->vtable = inode;
#endif
	inode = tux3_iget(sbi, TUX_ATABLE_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->atable = inode;

	inode = tux3_iget(sbi, TUX_ROOTDIR_INO);
	if (IS_ERR(inode))
		goto error_inode;
	sbi->rootdir = inode;

	err = replay_stage2(rp);
	if (err) {
		rp = NULL;
		goto error;
	}

	return rp;

error_inode:
	err = PTR_ERR(inode);
error:
	if (!IS_ERR_OR_NULL(rp))
		replay_stage3(rp, 0);
	__tux3_put_super(sbi);

	return ERR_PTR(err);
}

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/statfs.h>

/* This will go to include/linux/magic.h */
#ifndef TUX3_SUPER_MAGIC
#define TUX3_SUPER_MAGIC	0x74757833
#endif

#define trace trace_on

/* FIXME: this should be mount option? */
int tux3_trace;
module_param(tux3_trace, int, 0644);

static struct kmem_cache *tux_inode_cachep;

static void tux3_inode_init_once(void *mem)
{
	tuxnode_t *tuxi = mem;

	INIT_LIST_HEAD(&tuxi->alloc_list);
	INIT_LIST_HEAD(&tuxi->orphan_list);
	inode_init_once(&tuxi->vfs_inode);
}

static int __init tux3_init_inodecache(void)
{
	tux_inode_cachep = kmem_cache_create("tux3_inode_cache",
		sizeof(tuxnode_t), 0, (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
		tux3_inode_init_once);
	if (tux_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void __exit tux3_destroy_inodecache(void)
{
	kmem_cache_destroy(tux_inode_cachep);
}

static struct inode *tux3_alloc_inode(struct super_block *sb)
{
	static struct timespec epoch;
	tuxnode_t *tuxi = kmem_cache_alloc(tux_inode_cachep, GFP_KERNEL);

	if (!tuxi)
		return NULL;
	tuxi->btree = (struct btree){ };
	tuxi->present = 0;
	tuxi->xcache = NULL;

	/* uninitialized stuff by alloc_inode() */
	tuxi->vfs_inode.i_version = 1;
	tuxi->vfs_inode.i_atime = epoch;
	tuxi->vfs_inode.i_mtime = epoch;
	tuxi->vfs_inode.i_ctime = epoch;
	tuxi->vfs_inode.i_mode = 0;
	return &tuxi->vfs_inode;
}

static void tux3_destroy_inode(struct inode *inode)
{
	BUG_ON(!list_empty(&tux_inode(inode)->alloc_list));
	BUG_ON(!list_empty(&tux_inode(inode)->orphan_list));
	kmem_cache_free(tux_inode_cachep, tux_inode(inode));
}

static void tux3_write_super(struct super_block *sb)
{
	lock_super(sb);
	if (save_sb(tux_sb(sb))) {
		printk(KERN_ERR "TUX3: unable to write superblock\n");
		return;
	}
	sb->s_dirt = 0;
	unlock_super(sb);
}

static int tux3_sync_fs(struct super_block *sb, int wait)
{
	tux3_write_super(sb); /* FIXME: error handling */
	return 0;
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

	tux3_write_super(sb);

	__tux3_put_super(sbi);
	sb->s_fs_info = NULL;
	kfree(sbi);
}

static int tux3_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct sb *sbi = tux_sb(sb);

	buf->f_type = sb->s_magic;
	buf->f_bsize = sbi->blocksize;
	buf->f_blocks = sbi->volblocks;
	buf->f_bfree = sbi->freeblocks;
	buf->f_bavail = sbi->freeblocks;
#if 0
	buf->f_files = buf->f_blocks << (sbi->clus_bits - EXFAT_CHUNK_BITS) / 3;
	buf->f_ffree = buf->f_blocks << (sbi->clus_bits - EXFAT_CHUNK_BITS) / 3;
	buf->f_fsid.val[0] = sbi->serial_number;
	/*buf->f_fsid.val[1];*/
#endif
	buf->f_namelen = TUX_NAME_LEN;
//	buf->f_frsize = sbi->blocksize;

	return 0;
}

static const struct super_operations tux3_super_ops = {
	.alloc_inode	= tux3_alloc_inode,
	.destroy_inode	= tux3_destroy_inode,
	.evict_inode	= tux3_evict_inode,
	.write_inode	= tux3_write_inode,
	.write_super	= tux3_write_super,
	.sync_fs	= tux3_sync_fs,
	.put_super	= tux3_put_super,
	.statfs		= tux3_statfs,
};

static int tux3_fill_super(struct super_block *sb, void *data, int silent)
{
	struct sb *sbi;
	struct replay *rp = NULL;
	int err, blocksize;

	sbi = kzalloc(sizeof(struct sb), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sbi->vfs_sb = sb;
	sb->s_fs_info = sbi;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = TUX3_SUPER_MAGIC;
	sb->s_op = &tux3_super_ops;
	sb->s_time_gran = 1;

	err = -EIO;
	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to set blocksize\n");
		goto error;
	}

	if ((err = load_sb(sbi))) {
		if (!silent) {
			if (err == -EINVAL)
				warn("invalid superblock [%Lx]",
				     be64_to_cpup((__be64 *)sbi->super.magic));
			else
				warn("Unable to read superblock");
		}
		goto error;
	}

	if (sbi->blocksize != blocksize) {
		if (!sb_set_blocksize(sb, sbi->blocksize)) {
			printk(KERN_ERR "TUX3: blocksize too small for device.\n");
			goto error;
		}
	}
	warn("s_blocksize %lu", sb->s_blocksize);

	rp = tux3_init_fs(sbi);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}

	err = replay_stage3(rp, 1);
	if (err) {
		rp = NULL;
		goto error;
	}

	sb->s_root = d_alloc_root(sbi->rootdir);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto error;
	}

	return 0;

error:
	if (!IS_ERR_OR_NULL(rp))
		replay_stage3(rp, 0);
	__tux3_put_super(sbi);
	kfree(sbi);

	return err;
}

static struct dentry *tux3_mount(struct file_system_type *fs_type, int flags,
	const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, tux3_fill_super);
}

static struct file_system_type tux3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tux3",
	.fs_flags	= FS_REQUIRES_DEV,
	.mount		= tux3_mount,
	.kill_sb	= kill_block_super,
};

static int __init init_tux3(void)
{
	int err = tux3_init_inodecache();
	if (err)
		return err;
	return register_filesystem(&tux3_fs_type);
}

static void __exit exit_tux3(void)
{
	unregister_filesystem(&tux3_fs_type);
	tux3_destroy_inodecache();
}

module_init(init_tux3);
module_exit(exit_tux3);
MODULE_LICENSE("GPL");
#endif /* !__KERNEL__ */
