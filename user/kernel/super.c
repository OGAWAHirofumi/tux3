/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include <linux/module.h>
#include <linux/statfs.h>
#include "tux3.h"

static struct kmem_cache *tux_inode_cachep;

static void tux3_inode_init_once(void *mem)
{
	tuxnode_t *tuxi = mem;
	INIT_LIST_HEAD(&tuxi->dirty);
	inode_init_once(&tuxi->vfs_inode);
}

static int __init tux3_init_inodecache(void)
{
	tux_inode_cachep = kmem_cache_create("tux_inode_cache",
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
	BUG_ON(!list_empty(&tuxi->dirty));

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
	kmem_cache_free(tux_inode_cachep, tux_inode(inode));
}

static int tux_load_sb(struct super_block *sb, struct root *iroot, int silent)
{
	struct buffer_head *bh;
	int err;

	BUG_ON(SB_LOC < sb->s_blocksize);
	bh = sb_bread(sb, SB_LOC >> sb->s_blocksize_bits);
	if (!bh) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to read superblock\n");
		return -EIO;
	}
	err = unpack_sb(tux_sb(sb), bufdata(bh), iroot, silent);
	/* FIXME: this is needed? */
	memcpy(&tux_sb(sb)->super, bufdata(bh), sizeof(tux_sb(sb)->super));
	brelse(bh);

	return err;
}

static void tux3_write_super(struct super_block *sb)
{
	struct buffer_head *bh;

	BUG_ON(SB_LOC < sb->s_blocksize);
	bh = vol_bread(tux_sb(sb), SB_LOC >> sb->s_blocksize_bits);
	if (!bh) {
		printk(KERN_ERR "TUX3: unable to read superblock\n");
		return;
	}
	pack_sb(tux_sb(sb), bufdata(bh));
	brelse_dirty(bh);
	sb->s_dirt = 0;
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

	/* FIXME: remove this, then use sb->s_dirt instead */
	tux3_write_super(sb);

	destroy_defree(&sbi->defree);
	iput(sbi->atable);
	iput(sbi->bitmap);
	iput(sbi->volmap);
	iput(sbi->logmap);

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
	.delete_inode	= tux3_delete_inode,
	.clear_inode	= tux3_clear_inode,
	.write_inode	= tux3_write_inode,
	.write_super	= tux3_write_super,
	.put_super	= tux3_put_super,
	.statfs		= tux3_statfs,
};

static int tux3_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tux_iattr iattr;
	struct sb *sbi;
	struct root iroot;
	int err, blocksize;

	sbi = kzalloc(sizeof(struct sb), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sbi->vfs_sb = sb;
	sb->s_fs_info = sbi;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = 0x54555833;
	sb->s_op = &tux3_super_ops;
	sb->s_time_gran = 1;

	mutex_init(&sbi->loglock);
	INIT_LIST_HEAD(&sbi->dirty_inodes);

	err = -EIO;
	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to set blocksize\n");
		goto error;
	}

	err = tux_load_sb(sb, &iroot, silent);
	if (err)
		goto error;
	printk("%s: depth %Lu, block %Lu\n",
	       __func__, (L)iroot.depth, (L)iroot.block);
	printk("%s: blocksize %u, blockbits %u, blockmask %08x\n",
	       __func__, sbi->blocksize, sbi->blockbits, sbi->blockmask);
	printk("%s: volblocks %Lu, freeblocks %Lu, nextalloc %Lu\n",
	       __func__, sbi->volblocks, sbi->freeblocks, sbi->nextalloc);
	printk("%s: freeatom %u, atomgen %u\n",
	       __func__, sbi->freeatom, sbi->atomgen);

	if (sbi->blocksize != blocksize) {
		if (!sb_set_blocksize(sb, sbi->blocksize)) {
			printk(KERN_ERR "TUX3: blocksize too small for device.\n");
			goto error;
		}
	}
	printk("%s: s_blocksize %lu\n", __func__, sb->s_blocksize);

	err = -ENOMEM;
	sbi->volmap = tux_new_volmap(tux_sb(sb));
	if (!sbi->volmap)
		goto error;
	insert_inode_hash(sbi->volmap);

	/* Initialize itable btree */
	init_btree(itable_btree(sbi), sbi, iroot, &itable_ops);

//	struct inode *vtable;
	sbi->bitmap = tux3_iget(sb, TUX_BITMAP_INO);
	err = PTR_ERR(sbi->bitmap);
	if (IS_ERR(sbi->bitmap))
		goto error_bitmap;

	sbi->rootdir = tux3_iget(sb, TUX_ROOTDIR_INO);
	err = PTR_ERR(sbi->rootdir);
	if (IS_ERR(sbi->rootdir))
		goto error_rootdir;

	sbi->atable = tux3_iget(sb, TUX_ATABLE_INO);
	err = PTR_ERR(sbi->atable);
	if (IS_ERR(sbi->atable))
		goto error_atable;

	err = -ENOMEM;
	sbi->logmap = tux_new_inode(sbi->rootdir, &iattr, 0);
	if (!sbi->logmap)
		goto error_logmap;

	sb->s_root = d_alloc_root(sbi->rootdir);
	if (!sb->s_root)
		goto error_alloc_root;

	return 0;

error_alloc_root:
	iput(sbi->logmap);
error_logmap:
	iput(sbi->atable);
error_atable:
	iput(sbi->rootdir);
error_rootdir:
	iput(sbi->bitmap);
error_bitmap:
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
