/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

static void inode_init_once(struct inode *inode)
{
	memset(inode, 0, sizeof(*inode));

	spin_lock_init(&inode->i_lock);
	mutex_init(&inode->i_mutex);
	INIT_HLIST_NODE(&inode->i_hash);
}

#include "kernel/super.c"

void inode_init(struct tux3_inode *tuxnode, struct sb *sb, umode_t mode)
{
	struct inode *inode = &tuxnode->vfs_inode;

	tux3_inode_init_once(tuxnode);
	tux3_inode_init_always(tuxnode);

	inode->i_sb	= sb;
	inode->i_mode	= mode;
	inode->i_nlink	= 1;
	atomic_set(&inode->i_count, 1);
}

void free_inode_check(struct tux3_inode *tuxnode)
{
	struct inode *inode = &tuxnode->vfs_inode;

	tux3_check_destroy_inode(inode);

	assert(hlist_unhashed(&inode->i_hash));
	assert(inode->i_state == I_FREEING);
	assert(mapping(inode));
}

int put_super(struct sb *sb)
{
	/*
	 * FIXME: Some test programs may not be loading inodes.
	 * All programs should load all internal inodes.
	 */

	__tux3_put_super(sb);

	inode_leak_check();

	return 0;
}

/* Clear first and last block to get rid of other magic */
static int clear_other_magic(struct sb *sb)
{
	struct {
		loff_t loc;
		unsigned len;
	} area[] = {
		{ 0, SB_LOC },
		{ (sb->volblocks - 1) << sb->blockbits, sb->blocksize },
	};
	void *data;
	unsigned maxlen = 0;
	int err;

	for (int i = 0; i < ARRAY_SIZE(area); i++)
		maxlen = max(maxlen, area[i].len);

	data = malloc(maxlen);
	if (!data)
		return -ENOMEM;
	memset(data, 0, maxlen);

	for (int i = 0; i < ARRAY_SIZE(area); i++) {
		err = devio(WRITE, sb->dev, area[i].loc, data, area[i].len);
		if (err)
			break;
	}

	free(data);

	return err;
}

static int reserve_superblock(struct sb *sb)
{
	/* Always 8K regardless of blocksize */
	struct block_segment seg = {
		.block = 0,
		.count = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits),
	};
	int err;

	trace("reserve superblock");

	/* Reserve blocks from 0 to 8KB */
	err = balloc_use(sb, &seg, 1);
	if (err < 0)
		return err;

	log_balloc(sb, seg.block, seg.count);
	trace("reserve %Lx", seg.block);

	return 0;
}

int make_tux3(struct sb *sb)
{
	int err;

	err = clear_other_magic(sb);
	if (err)
		return err;

	change_begin_atomic(sb);

	trace("create bitmap");
	sb->bitmap = create_internal_inode(sb, TUX_BITMAP_INO, NULL);
	if (IS_ERR(sb->bitmap)) {
		err = PTR_ERR(sb->bitmap);
		goto error_change_end;
	}

	sb->countmap = create_internal_inode(sb, TUX_COUNTMAP_INO, NULL);
	if (IS_ERR(sb->countmap)) {
		err = PTR_ERR(sb->countmap);
		goto error_change_end;
	}

	change_end_atomic(sb);

	/* Set fake backend mark to modify backend objects. */
	tux3_start_backend(sb);
	err = reserve_superblock(sb);
	tux3_end_backend();
	if (err)
		goto error;

	change_begin_atomic(sb);
#if 0
	trace("create version table");
	sb->vtable = create_internal_inode(sb, TUX_VTABLE_INO, NULL);
	if (IS_ERR(sb->vtable)) {
		err = PTR_ERR(sb->vtable);
		goto error_change_end;
	}
#endif
	trace("create atom dictionary");
	sb->atable = create_internal_inode(sb, TUX_ATABLE_INO, NULL);
	if (IS_ERR(sb->atable)) {
		err = PTR_ERR(sb->atable);
		goto error_change_end;
	}

	trace("create root directory");
	struct tux_iattr root_iattr = { .mode = S_IFDIR | 0755, };
	sb->rootdir = create_internal_inode(sb, TUX_ROOTDIR_INO, &root_iattr);
	if (IS_ERR(sb->rootdir)) {
		err = PTR_ERR(sb->rootdir);
		goto error_change_end;
	}

	change_end_atomic(sb);

	err = sync_super(sb);
	if (err)
		goto error;

	show_buffers(mapping(sb->bitmap));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->volmap->map);

	return 0;

error_change_end:
	change_end_atomic(sb);
error:
	tux3_err(sb, "eek, %s", strerror(-err));
	iput(sb->bitmap);
	sb->bitmap = NULL;

	return err;
}

int tux3_init_mem(void)
{
	return tux3_init_hole_cache();
}

void tux3_exit_mem(void)
{
	tux3_destroy_hole_cache();
}
