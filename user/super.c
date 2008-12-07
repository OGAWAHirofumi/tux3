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

#include "kernel/super.c"

int load_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	int err = diskread(sb->devmap->dev->fd, super, sizeof(*super), SB_LOC);
	if (err)
		return err;
	err = unpack_sb(sb, super, 0);
	if (err)
		return err;
	return 0;
}

int save_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	pack_sb(sb, super);
	return diskwrite(sb->devmap->dev->fd, super, sizeof(*super), SB_LOC);
}

int sync_super(struct sb *sb)
{
	int err;
	printf("sync bitmap\n");
	if ((err = tuxsync(sb->bitmap)))
		return err;
	printf("sync rootdir\n");
	if ((err = tuxsync(sb->rootdir)))
		return err;
	printf("sync atom table\n");
	if ((err = tuxsync(sb->atable)))
		return err;
	printf("sync devmap\n");
	if ((err = flush_buffers(sb->devmap)))
		return err;
	printf("sync super\n");
	if ((err = save_sb(sb)))
		return err;
	return 0;
}

int make_tux3(struct sb *sb, int fd)
{
	int err = 0;
	trace("create bitmap");
	if (!(sb->bitmap = new_inode(sb, TUX_BITMAP_INO)))
		goto eek;

	trace("reserve superblock");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++) {
		block_t block = balloc_from_range(sb->bitmap, i, 1);
		trace("reserve %Lx", (L)block); // error ???
	}

	trace("create inode table");
	sb->itable = new_btree(sb, &itable_ops);
	if (!sb->itable.ops)
		goto eek;
	sb->itable.entries_per_leaf = 64; // !!! should depend on blocksize
	sb->bitmap->i_size = (sb->volblocks + 7) >> 3;
	trace("create bitmap inode");
	if (make_inode(sb->bitmap, &(struct tux_iattr){ }))
		goto eek;
	trace("create version table");
	if (!(sb->vtable = new_inode(sb, TUX_VTABLE_INO)))
		goto eek;
	if (make_inode(sb->vtable, &(struct tux_iattr){ }))
		goto eek;
	trace("create root directory");
	if (!(sb->rootdir = new_inode(sb, TUX_ROOTDIR_INO)))
		goto eek;
	if (make_inode(sb->rootdir, &(struct tux_iattr){ .mode = S_IFDIR | 0755 }))
		goto eek;
	trace("create atom dictionary");
	if (!(sb->atable = new_inode(sb, TUX_ATABLE_INO)))
		goto eek;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->atomgen = 1; // atom 0 not allowed, means end of atom freelist
	if (make_inode(sb->atable, &(struct tux_iattr){ }))
		goto eek;
	if ((err = sync_super(sb)))
		goto eek;

	show_buffers(mapping(sb->bitmap));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->devmap);
	return 0;
eek:
	free_btree(&sb->itable);
	free_inode(sb->bitmap);
	sb->bitmap = NULL;
	sb->itable = (struct btree){ };
	if (err) {
		warn("eek, %s", strerror(-err));
		return err;
	}
	return -ENOSPC; // just guess
}
