/*
 * tux3/super.c
 * Copyright (c) 2008, Daniel Phillips
 * Portions copyright (c) 2008, Maciej Zenczykowski
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/statfs.h>

#include "tux3.h"

static struct kmem_cache *tux_inode_cachep;

static void tux3_inode_init_once(struct kmem_cache *cachep, void *mem)
{
	inode_init_once(&((tuxnode_t *)mem)->vfs_inode);
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
	tuxnode_t *tuxi = kmem_cache_alloc(tux_inode_cachep, GFP_KERNEL);
	if (!tuxi)
		return NULL;
	tuxi->btree = (struct btree){};
	tuxi->inum = 0;
	tuxi->present = 0;
	tuxi->xcache = NULL;
	return &tuxi->vfs_inode;
}

static void tux3_destroy_inode(struct inode *inode)
{
	kmem_cache_free(tux_inode_cachep, tux_inode(inode));
}

static int tux_load_sb(struct super_block *sb, int silent)
{
	struct sb *sbi = tux_sb(sb);
	struct buffer_head *bh = NULL;
	int err;

	err = -EIO;
	bh = sb_bread(sb, SB_LOC >> sb->s_blocksize_bits);
	if (!bh) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to read superblock\n");
		goto error;
	}

	err = -EINVAL;
	struct disksuper *disk = (struct disksuper *)bh->b_data;
	if (memcmp(disk->magic, (char[])SB_MAGIC, sizeof(disk->magic))) {
		if (!silent)
			printk(KERN_ERR "TUX3: invalid superblock [%Lx]",
			       (L)from_be_u64(*(be_u64 *)disk->magic));
		goto error;
	}

	int blockbits = from_be_u16(disk->blockbits);
	u64 iroot = from_be_u64(disk->iroot);

	sbi->itable = (struct btree){
		.sb	= sbi,
		.ops	= &itable_ops,
		.root	= (struct root){
			.depth = iroot >> 48,
			.block = iroot & (-1ULL >> 16)
		},
		.entries_per_leaf = 1 << (blockbits - 6),
	};
//	sbi->rootbuf;
	sbi->blockbits = blockbits;
	sbi->blocksize = 1 << blockbits;
	sbi->blockmask = (1 << blockbits) - 1;
	sbi->volblocks = from_be_u64(disk->volblocks);
	sbi->freeblocks = from_be_u64(disk->freeblocks);
	sbi->nextalloc = from_be_u64(disk->nextalloc);
	sbi->atomgen = from_be_u32(disk->atomgen);
	sbi->freeatom = from_be_u32(disk->freeatom);

	brelse(bh);

	return 0;

error:
	brelse(bh);
	return err;
}

static void tux3_write_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);
	struct buffer_head *bh;

	bh = sb_bread(sb, SB_LOC >> sb->s_blocksize_bits);
	if (!bh) {
		printk(KERN_ERR "TUX3: unable to read superblock\n");
		return;
	}

	struct disksuper *disk = bufdata(bh);
	disk->blockbits = to_be_u16(sbi->blockbits);
	disk->volblocks = to_be_u64(sbi->volblocks);
	disk->nextalloc = to_be_u64(sbi->nextalloc); // probably does not belong here
	disk->freeatom = to_be_u32(sbi->freeatom); // probably does not belong here
	disk->atomgen = to_be_u32(sbi->atomgen); // probably does not belong here
	disk->freeblocks = to_be_u64(sbi->freeblocks); // probably does not belong here
	disk->iroot = to_be_u64((u64)sbi->itable.root.depth << 48 | sbi->itable.root.block);
	brelse_dirty(bh);

	sb->s_dirt = 0;
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

	/* FIXME: remove this, then use sb->s_dirt instead */
	tux3_write_super(sb);

	iput(sbi->atable);
	iput(sbi->bitmap);

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
	.write_super	= tux3_write_super,
	.put_super	= tux3_put_super,
	.statfs		= tux3_statfs,
	.clear_inode	= tux3_clear_inode,
	.write_inode	= tux3_write_inode,
};

static int tux3_fill_super(struct super_block *sb, void *data, int silent)
{
	struct sb *sbi;
	int err, blocksize;

	sbi = kzalloc(sizeof(struct sb), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = 0x54555833;
	sb->s_op = &tux3_super_ops;
	sb->s_time_gran = 1;

	sbi->vfs_sb = sb;
	sbi->entries_per_node = 20;
//	sbi->max_inodes_per_block = 64;
//	sbi->version;
//	sbi->atomref_base;
//	sbi->unatom_base;

	err = -EIO;
	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to set blocksize\n");
		goto error;
	}

	err = tux_load_sb(sb, silent);
	if (err)
		goto error;
	printk("%s: sb %p, ops %p, depth %Lu, block %Lu, entries_per_leaf %d\n",
	       __func__,
	       sbi->itable.sb, sbi->itable.ops,
	       (L)sbi->itable.root.depth, (L)sbi->itable.root.block,
	       sbi->itable.entries_per_leaf);
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

//	struct inode *vtable;
	sbi->bitmap = tux3_iget(sb, TUX_BITMAP_INO);
	err = PTR_ERR(sbi->bitmap);
	if (IS_ERR(sbi->bitmap))
		goto error;

	sbi->rootdir = tux3_iget(sb, TUX_ROOTDIR_INO);
	err = PTR_ERR(sbi->rootdir);
	if (IS_ERR(sbi->rootdir))
		goto error_bitmap;

	sbi->atable = tux3_iget(sb, TUX_ATABLE_INO);
	err = PTR_ERR(sbi->atable);
	if (IS_ERR(sbi->atable))
		goto error_rootdir;

	err = -ENOMEM;
	sb->s_root = d_alloc_root(sbi->rootdir);
	if (!sb->s_root)
		goto error_atable;

	return 0;

error_atable:
	iput(sbi->atable);
error_rootdir:
	iput(sbi->rootdir);
error_bitmap:
	iput(sbi->bitmap);
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

module_init(init_tux3)
module_exit(exit_tux3)
MODULE_LICENSE("GPL");
