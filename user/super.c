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

#ifdef ATOMIC
static void clean_dirty_buffer(const char *str, struct list_head *head)
{
	struct buffer_head *buf, *n;

	list_for_each_entry_safe(buf, n, head, link) {
		trace(">>> clean %s buffer %Lx:%Lx, count %d, state %d",
		      str, (L)tux_inode(buffer_inode(buf))->inum,
		      (L)bufindex(buf), bufcount(buf),
		      buf->state);
		assert(buffer_dirty(buf));
		set_buffer_clean(buf);
	}
}

static void clean_dirty_inode(const char *str, struct inode *inode)
{
	if (inode->state & I_DIRTY) {
		trace(">>> clean %s inode i_count %d, state %x",
		      str, atomic_read(&inode->i_count), inode->state);
		del_defer_alloc_inum(inode);
		clear_inode(inode);
	}
}
#endif

static void cleanup_garbage_for_debugging(struct sb *sb)
{
#ifdef ATOMIC
	/*
	 * Pinned buffer is not flushing always, it is normal. So,
	 * this clean those for unmount to check buffer debugging
	 */
	if (sb->bitmap) {
		clean_dirty_buffer("bitmap", &mapping(sb->bitmap)->dirty);
		clean_dirty_inode("bitmap", sb->bitmap);
	}
	clean_dirty_buffer("pinned", &sb->pinned);

	/* defree must be flushed for each delta */
	assert(flink_empty(&sb->defree.head)||flink_is_last(&sb->defree.head));
	destroy_defer_bfree(&sb->derollup);
	destroy_defer_bfree(&sb->defree);
#else /* !ATOMIC */
	/*
	 * Clean garbage (atomic commit) stuff. Don't forget to update
	 * this, if you update the atomic commit.
	 */
	log_finish(sb);

	sb->logchain = 0;
	sb->logbase = 0;
	sb->logthis = sb->lognext = 0;
	if (sb->logmap)
		invalidate_buffers(sb->logmap->map);

	assert(flink_empty(&sb->defree.head)||flink_is_last(&sb->defree.head));
	destroy_defer_bfree(&sb->defree);
	assert(flink_empty(&sb->derollup.head));
	assert(list_empty(&sb->pinned));
#endif /* !ATOMIC */
}

int put_super(struct sb *sb)
{
	/*
	 * FIXME: Some test programs may not be loading inodes.
	 * All programs should load all internal inodes.
	 */

	cleanup_garbage_for_debugging(sb);

	if (sb->vtable)
		iput(sb->vtable);
	if (sb->rootdir)
		iput(sb->rootdir);
	if (sb->atable)
		iput(sb->atable);
	if (sb->bitmap)
		iput(sb->bitmap);
	if (sb->logmap)
		iput(sb->logmap);
	if (sb->volmap)
		iput(sb->volmap);

	return 0;
}

static int clear_other_magic(struct sb *sb)
{
	int err;

	/* Clear first and last block to get rid of other magic */
	for (int i = 0; i <= 1; i++) {
		loff_t loc = (loff_t[2]){ 0, (sb->volblocks - 1) << sb->blockbits }[i];
		unsigned len = (loff_t[2]){ SB_LOC, sb->blocksize }[i];
		char data[len];
		memset(data, 0, len);
		err = devio(WRITE, sb->dev, loc, data, len);
		if (err)
			break;
	}
	return err;
}

static struct inode *create_internal_inode(struct sb *sb, inum_t inum,
					   struct tux_iattr *iattr)
{
	struct inode *dir = &(struct inode){
		.i_sb = sb,
		.i_mode = S_IFDIR | 0755,
	};
	struct tux_iattr *null_iattr = &(struct tux_iattr){};
	struct inode *inode;

	if (iattr == NULL)
		iattr = null_iattr;

	inode = __tux_create_inode(dir, inum, iattr, 0);
	assert(IS_ERR(inode) || inode->inum == inum);
	return inode;
}

/*
 * Internal inode (e.g. bitmap inode) yet may not be written. So, if
 * there is no inode, create inode instead.
 */
struct inode *iget_or_create_inode(struct sb *sb, inum_t inum)
{
	struct inode *inode;

	inode = iget(sb, inum);
	if (IS_ERR(inode) && PTR_ERR(inode) == -ENOENT)
		inode = create_internal_inode(sb, inum, NULL);
	return inode;
}

static int reserve_superblock(struct sb *sb)
{
	trace("reserve superblock");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++) {
		block_t block = balloc_from_range(sb, i, 1, 1);
		if (block == -1)
			return -ENOSPC; // fix error code ???
		log_balloc(sb, block, 1);
		trace("reserve %Lx", (L)block);
	}

	return 0;
}

int make_tux3(struct sb *sb)
{
	int err;

	err = clear_other_magic(sb);
	if (err)
		return err;

	trace("create inode table");
	init_btree(itable_btree(sb), sb, no_root, &itable_ops);

	trace("create bitmap");
	sb->bitmap = create_internal_inode(sb, TUX_BITMAP_INO, NULL);
	if (IS_ERR(sb->bitmap)) {
		err = PTR_ERR(sb->bitmap);
		goto eek;
	}

	if (reserve_superblock(sb) < 0)
		goto eek;

	trace("create version table");
	sb->vtable = create_internal_inode(sb, TUX_VTABLE_INO, NULL);
	if (IS_ERR(sb->vtable)) {
		err = PTR_ERR(sb->vtable);
		goto eek;
	}

	trace("create atom dictionary");
	sb->atable = create_internal_inode(sb, TUX_ATABLE_INO, NULL);
	if (IS_ERR(sb->atable)) {
		err = PTR_ERR(sb->atable);
		goto eek;
	}
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->atomgen = 1; // atom 0 not allowed, means end of atom freelist

	trace("create root directory");
	struct tux_iattr root_iattr = { .mode = S_IFDIR | 0755, };
	sb->rootdir = create_internal_inode(sb, TUX_ROOTDIR_INO, &root_iattr);
	if (IS_ERR(sb->rootdir)) {
		err = PTR_ERR(sb->rootdir);
		goto eek;
	}

	if ((err = sync_super(sb)))
		goto eek;

	show_buffers(mapping(sb->bitmap));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->volmap->map);
	return 0;
eek:
	if (err)
		warn("eek, %s", strerror(-err));
	iput(sb->bitmap);
	sb->bitmap = NULL;
	return err ? err : -ENOSPC; // just guess
}
