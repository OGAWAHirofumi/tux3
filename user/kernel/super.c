/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 * Licensed under the GPL version 2
 */

#include "tux3.h"
#include "filemap_hole.h"
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
#endif

#ifdef __KERNEL__
#define BUFFER_LINK	b_assoc_buffers
#else
#define BUFFER_LINK	link
#endif

static void cleanup_dirty_buffers(struct inode *inode, struct list_head *head,
				  unsigned delta)
{
	struct buffer_head *buffer, *n;

	list_for_each_entry_safe(buffer, n, head, BUFFER_LINK) {
		trace(">>> clean inum %Lx, buffer %Lx, count %d",
		      tux_inode(inode)->inum, bufindex(buffer),
		      bufcount(buffer));
		assert(buffer_dirty(buffer));
		tux3_clear_buffer_dirty(buffer, delta);
	}
}

static void cleanup_dirty_inode(struct inode *inode)
{
	if (inode->i_state & I_DIRTY) {
		trace(">>> clean inum %Lx, i_count %d, i_state %lx",
		      tux_inode(inode)->inum, atomic_read(&inode->i_count),
		      inode->i_state);
		del_defer_alloc_inum(inode);
		tux3_clear_dirty_inode(inode);
	}
}

/*
 * Some inode/buffers are always (re-)dirtied, so we have to cleanup
 * those for umount.
 */
static void cleanup_dirty_for_umount(struct sb *sb)
{
	unsigned rollup = sb->rollup;

	/*
	 * Pinned buffer and bitmap are not flushing always, it is
	 * normal. So, this clean those for unmount.
	 */
	if (sb->bitmap) {
		struct list_head *head = tux3_dirty_buffers(sb->bitmap, rollup);
		cleanup_dirty_buffers(sb->bitmap, head, rollup);
		cleanup_dirty_inode(sb->bitmap);
	}
	if (sb->volmap) {
		cleanup_dirty_buffers(sb->volmap, &sb->rollup_buffers, rollup);
		/*
		 * FIXME: mark_buffer_dirty() for rollup buffers marks
		 * volmap as I_DIRTY_PAGES (we don't need I_DIRTY_PAGES
		 * actually) without changing tuxnode->flags.
		 *
		 * So this is called to clear I_DIRTY_PAGES.
		 */
		cleanup_dirty_inode(sb->volmap);
	}

	/* orphan_add should be empty */
	assert(list_empty(&sb->orphan_add));
	/* Deferred orphan deletion request is not flushed for each delta  */
	clean_orphan_list(&sb->orphan_del);

	/* defree must be flushed for each delta */
	assert(flink_empty(&sb->defree.head)||flink_is_last(&sb->defree.head));
}

static void __tux3_put_super(struct sb *sbi)
{
	cleanup_dirty_for_umount(sbi);

	tux3_exit_flusher(sbi);

	/* All forked buffers should be freed here */
	free_forked_buffers(sbi, NULL, 1);

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

	/* Cleanup flusher after inode was evicted */
	tux3_cleanup_flusher(sbi);

	/* FIXME: add more sanity check */
	assert(list_empty(&sbi->alloc_inodes));
	assert(link_empty(&sbi->forked_buffers));
}

static struct inode *create_internal_inode(struct sb *sbi, inum_t inum,
					   struct tux_iattr *iattr)
{
	static struct tux_iattr null_iattr;
	struct inode *dir = &(struct inode){
		.i_sb = vfs_sb(sbi),
		.i_mode = S_IFDIR | 0755,
	};
	struct inode *inode;

	if (iattr == NULL)
		iattr = &null_iattr;

	inode = tux_create_specific_inode(dir, inum, iattr, 0);
	assert(IS_ERR(inode) || tux_inode(inode)->inum == inum);
	unlock_new_inode(inode);
	return inode;
}

/*
 * Internal inode (e.g. bitmap inode) yet may not be written. So, if
 * there is no inode, create inode instead.
 */
static struct inode *iget_or_create_inode(struct sb *sbi, inum_t inum)
{
	struct inode *inode;

	inode = tux3_iget(sbi, inum);
	if (IS_ERR(inode) && PTR_ERR(inode) == -ENOENT)
		inode = create_internal_inode(sbi, inum, NULL);
	return inode;
}

struct replay *tux3_init_fs(struct sb *sbi)
{
	struct replay *rp = NULL;
	struct inode *inode;
	int err;

	/* Initialize flusher before setup inode */
	err = tux3_setup_flusher(sbi);
	if (err) {
		tux3_err(sbi, "failed to initialize flusher");
		goto error;
	}

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

	err = tux3_init_flusher(sbi);
	if (err)
		goto error;

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

static void tux3_inode_init_once(void *mem)
{
	struct tux3_inode *tuxnode = mem;
	struct inode *inode = &tuxnode->vfs_inode;
	int i;

	INIT_LIST_HEAD(&tuxnode->alloc_list);
	INIT_LIST_HEAD(&tuxnode->orphan_list);
	spin_lock_init(&tuxnode->hole_extents_lock);
	INIT_LIST_HEAD(&tuxnode->hole_extents);
	spin_lock_init(&tuxnode->lock);
	/* Initialize inode_delta_dirty */
	for (i = 0; i < ARRAY_SIZE(tuxnode->i_ddc); i++) {
		INIT_LIST_HEAD(&tuxnode->i_ddc[i].dirty_buffers);
		INIT_LIST_HEAD(&tuxnode->i_ddc[i].dirty_holes);
		INIT_LIST_HEAD(&tuxnode->i_ddc[i].dirty_list);
		/* For debugging, set invalid value to ->present */
		tuxnode->i_ddc[i].idata.present = TUX3_INVALID_PRESENT;
	}

	/* Initialize generic part */
	inode_init_once(inode);
}

static void tux3_inode_init_always(struct tux3_inode *tuxnode)
{
	static struct timespec epoch;
	struct inode *inode = &tuxnode->vfs_inode;

	tuxnode->btree		= (struct btree){ };
	tuxnode->present	= 0;
	tuxnode->xcache		= NULL;
	tuxnode->flags		= 0;
#ifdef __KERNEL__
	tuxnode->io		= NULL;
#endif

	/* uninitialized stuff by alloc_inode() */
	inode->i_version	= 1;
	inode->i_atime		= epoch;
	inode->i_mtime		= epoch;
	inode->i_ctime		= epoch;
	inode->i_mode		= 0;
}

static int i_ddc_is_clean(struct inode *inode)
{
	struct tux3_inode *tuxnode = tux_inode(inode);
	int i;

	for (i = 0; i < ARRAY_SIZE(tuxnode->i_ddc); i++) {
		if (!list_empty(&tuxnode->i_ddc[i].dirty_buffers) ||
		    !list_empty(&tuxnode->i_ddc[i].dirty_list))
			return 0;
	}

	return 1;
}

static void tux3_check_destroy_inode(struct inode *inode)
{
	tux3_check_destroy_inode_flags(inode);
	assert(list_empty(&tux_inode(inode)->alloc_list));
	assert(list_empty(&tux_inode(inode)->orphan_list));
	assert(i_ddc_is_clean(inode));
}

#ifdef __KERNEL__
static struct kmem_cache *tux_inode_cachep;

static int __init tux3_init_inodecache(void)
{
	tux_inode_cachep = kmem_cache_create("tux3_inode_cache",
			sizeof(struct tux3_inode), 0,
			(SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
			tux3_inode_init_once);
	if (tux_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void tux3_destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(tux_inode_cachep);
}

static struct inode *tux3_alloc_inode(struct super_block *sb)
{
	struct tux3_inode *tuxnode;

	tuxnode = kmem_cache_alloc(tux_inode_cachep, GFP_KERNEL);
	if (!tuxnode)
		return NULL;

	tux3_inode_init_always(tuxnode);

	return &tuxnode->vfs_inode;
}

static void tux3_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(tux_inode_cachep, tux_inode(inode));
}

static void tux3_destroy_inode(struct inode *inode)
{
	tux3_check_destroy_inode(inode);
	call_rcu(&inode->i_rcu, tux3_i_callback);
}

static int tux3_sync_fs(struct super_block *sb, int wait)
{
	/* FIXME: We should support "wait" parameter. */
	trace_on("wait (%u) parameter is unsupported for now", wait);
	return force_delta(tux_sb(sb));
}

static void tux3_put_super(struct super_block *sb)
{
	struct sb *sbi = tux_sb(sb);

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
	buf->f_files = MAX_INODES;
	buf->f_ffree = sbi->freeinodes;
#if 0
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
	.dirty_inode	= tux3_dirty_inode,
	.drop_inode	= tux3_drop_inode,
	.evict_inode	= tux3_evict_inode,
	/* FIXME: we have to handle write_inode of sync (e.g. cache pressure) */
//	.write_inode	= tux3_write_inode,
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
	/*
	 * FIXME: atime can insert inode into dirty list unexpectedly.
	 * For now, doesn't support and disable atime.
	 */
	sb->s_flags |= MS_NOATIME;
	sb->s_magic = TUX3_SUPER_MAGIC;
	sb->s_op = &tux3_super_ops;
	sb->s_time_gran = 1;

	err = -EIO;
	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		if (!silent)
			printk(KERN_ERR "TUX3: unable to set blocksize\n");
		goto error_free;
	}

	/* Initialize and load sbi */
	err = load_sb(sbi);
	if (err) {
		if (!silent) {
			if (err == -EINVAL)
				tux3_err(sbi, "invalid superblock [%Lx]",
				     be64_to_cpup((__be64 *)sbi->super.magic));
			else
				tux3_err(sbi, "unable to read superblock");
		}
		goto error;
	}

	if (sbi->blocksize != blocksize) {
		if (!sb_set_blocksize(sb, sbi->blocksize)) {
			tux3_err(sbi, "blocksize too small for device");
			goto error;
		}
	}
	tux3_dbg("s_blocksize %lu", sb->s_blocksize);

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

	sb->s_root = d_make_root(sbi->rootdir);
	sbi->rootdir = NULL;	/* vfs takes care rootdir inode */
	if (!sb->s_root) {
		err = -ENOMEM;
		goto error;
	}

	return 0;

error:
	if (!IS_ERR_OR_NULL(rp))
		replay_stage3(rp, 0);
	__tux3_put_super(sbi);
error_free:
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
	int err;

	err = tux3_init_inodecache();
	if (err)
		goto error;

	err = tux3_init_hole_cache();
	if (err)
		goto error_hole;

	err = register_filesystem(&tux3_fs_type);
	if (err)
		goto error_fs;

	return 0;

error_fs:
	tux3_destroy_inodecache();
error_hole:
	tux3_destroy_hole_cache();
error:
	return err;
}

static void __exit exit_tux3(void)
{
	unregister_filesystem(&tux3_fs_type);
	tux3_destroy_hole_cache();
	tux3_destroy_inodecache();
}

module_init(init_tux3);
module_exit(exit_tux3);
MODULE_LICENSE("GPL");
#endif /* !__KERNEL__ */
