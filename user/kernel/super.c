/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include <linux/module.h>
#include <linux/statfs.h>
#include "tux3.h"

/* This will go to include/linux/magic.h */
#ifndef TUX3_SUPER_MAGIC
#define TUX3_SUPER_MAGIC	0x74757833
#endif

#define trace trace_on

/* FIXME: this should be mount option? */
int tux3_trace;
module_param(tux3_trace, bool, 0644);

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
	if (save_sb(tux_sb(sb))) {
		printk(KERN_ERR "TUX3: unable to write superblock\n");
		return;
	}
	sb->s_dirt = 0;
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

	/* FIXME: remove this, then use sb->s_dirt instead */
	tux3_write_super(sb);

	destroy_defer_bfree(&sbi->derollup);
	destroy_defer_bfree(&sbi->defree);
	iput(sbi->atable);
	iput(sbi->bitmap);
	iput(sbi->volmap);
	iput(sbi->logmap);

	BUG_ON(!list_empty(&sbi->alloc_inodes));
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
	.put_super	= tux3_put_super,
	.statfs		= tux3_statfs,
};

static int tux3_fill_super(struct super_block *sb, void *data, int silent)
{
	struct sb *sbi;
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

	err = -ENOMEM;
	sbi->volmap = tux_new_volmap(sbi);
	if (!sbi->volmap)
		goto error;

	sbi->logmap = tux_new_logmap(sbi);
	if (!sbi->logmap)
		goto error_logmap;

//	struct inode *vtable;
	sbi->bitmap = tux3_iget(sbi, TUX_BITMAP_INO);
	err = PTR_ERR(sbi->bitmap);
	if (IS_ERR(sbi->bitmap))
		goto error_bitmap;

	sbi->rootdir = tux3_iget(sbi, TUX_ROOTDIR_INO);
	err = PTR_ERR(sbi->rootdir);
	if (IS_ERR(sbi->rootdir))
		goto error_rootdir;

	sbi->atable = tux3_iget(sbi, TUX_ATABLE_INO);
	err = PTR_ERR(sbi->atable);
	if (IS_ERR(sbi->atable))
		goto error_atable;

	sb->s_root = d_alloc_root(sbi->rootdir);
	if (!sb->s_root)
		goto error_alloc_root;

	return 0;

error_alloc_root:
	iput(sbi->atable);
error_atable:
	iput(sbi->rootdir);
error_rootdir:
	iput(sbi->bitmap);
error_bitmap:
	iput(sbi->logmap);
error_logmap:
	iput(sbi->volmap);
error:
	kfree(sbi);
	return err;
}

static int tux3_get_sb(struct file_system_type *fs_type, int flags,
	const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_bdev(fs_type, flags, dev_name, data, tux3_fill_super, mnt);
}

static struct file_system_type tux3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tux3",
	.fs_flags	= FS_REQUIRES_DEV,
	.get_sb		= tux3_get_sb,
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
