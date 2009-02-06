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

int devio(int rw, struct dev *dev, loff_t offset, void *data, unsigned len)
{
	return ioabs(dev->fd, data, len, rw, offset);
}

#include "kernel/commit.c"

int load_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	int err = diskread(sb->dev->fd, super, sizeof(*super), SB_LOC);
	if (err)
		return err;
	err = unpack_sb(sb, super);
	if (err)
		return err;
	return 0;
}

int save_sb(struct sb *sb)
{
	struct disksuper *super = &sb->super;
	pack_sb(sb, super);
	return diskwrite(sb->dev->fd, super, sizeof(*super), SB_LOC);
}

int sync_super(struct sb *sb)
{
	int err;
	printf("sync rootdir\n");
	if ((err = tuxsync(sb->rootdir)))
		return err;
	printf("sync atom table\n");
	if ((err = tuxsync(sb->atable)))
		return err;
	printf("sync bitmap\n");
	if ((err = tuxsync(sb->bitmap)))
		return err;
	printf("sync volmap\n");
	if ((err = flush_buffers(sb->volmap->map)))
		return err;
	printf("sync super\n");
	if ((err = save_sb(sb)))
		return err;
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
		if ((err = diskwrite(sb->dev->fd, data, len, loc)))
			break;
	}
	return err;
}

int make_tux3(struct sb *sb)
{
	struct inode *dir = &(struct inode){ .i_sb = sb, .i_mode = S_IFDIR | 0755 };

	int err = clear_other_magic(sb);
	if (err)
		return err;

	trace("create bitmap");
	if (!(sb->bitmap = tux_new_inode(dir, &(struct tux_iattr){ }, 0)))
		goto eek;

	trace("reserve superblock");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++) {
		block_t block = balloc_from_range(sb, i, 1, 1);
		if (block == -1)
			goto eek;
		trace("reserve %Lx", (L)block); // error ???
	}

	trace("create inode table");
	err = new_btree(itable_btree(sb), sb, &itable_ops);
	if (err)
		goto eek;
	sb->bitmap->i_size = (sb->volblocks + 7) >> 3;
	trace("create bitmap inode");
	if (make_inode(sb->bitmap, TUX_BITMAP_INO))
		goto eek;
	trace("create version table");
	if (!(sb->vtable = tux_new_inode(dir, &(struct tux_iattr){ }, 0)))
		goto eek;
	if (make_inode(sb->vtable, TUX_VTABLE_INO))
		goto eek;
	trace("create root directory");
	if (!(sb->rootdir = tux_new_inode(dir, &(struct tux_iattr){ .mode = S_IFDIR | 0755 }, 0)))
		goto eek;
	if (make_inode(sb->rootdir, TUX_ROOTDIR_INO))
		goto eek;
	trace("create atom dictionary");
	if (!(sb->atable = tux_new_inode(dir, &(struct tux_iattr){ }, 0)))
		goto eek;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->atomgen = 1; // atom 0 not allowed, means end of atom freelist
	if (make_inode(sb->atable, TUX_ATABLE_INO))
		goto eek;
	if ((err = sync_super(sb)))
		goto eek;

	show_buffers(mapping(sb->bitmap));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->volmap->map);
	return 0;
eek:
	if (err)
		warn("eek, %s", strerror(-err));
	free_inode(sb->bitmap);
	sb->bitmap = NULL;
	return err ? err : -ENOSPC; // just guess
}
