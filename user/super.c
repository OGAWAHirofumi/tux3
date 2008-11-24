/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

int load_sb(SB)
{
	int err = diskread(sb->devmap->dev->fd, &sb->super, sizeof(struct disksuper), SB_LOC);
	if (err)
		return err;
	struct disksuper *disk = &sb->super;
	if (memcmp(disk->magic, (char[])SB_MAGIC, sizeof(disk->magic))) {
		warn("invalid superblock [%Lx]", (L)from_be_u64(*(be_u64 *)disk->magic));
		return -ENOENT;
	}
	int blockbits = from_be_u16(disk->blockbits);
	sb->volblocks = from_be_u64(disk->volblocks);
	sb->nextalloc = from_be_u64(disk->nextalloc);
	sb->atomgen = from_be_u32(disk->atomgen);
	sb->freeatom = from_be_u32(disk->freeatom);
	sb->freeblocks = from_be_u64(disk->freeblocks);
	u64 iroot = from_be_u64(disk->iroot);
	sb->itable.root = (struct root){ .depth = iroot >> 48, .block = iroot & (-1ULL >> 16) };
	sb->blockbits = blockbits;
	sb->blocksize = 1 << blockbits;
	sb->blockmask = (1 << blockbits) - 1;
	//hexdump(&sb->super, sizeof(sb->super));
	return 0;
}

int save_sb(SB)
{
	struct disksuper *disk = &sb->super;
	disk->blockbits = to_be_u16(sb->blockbits);
	disk->volblocks = to_be_u64(sb->volblocks);
	disk->nextalloc = to_be_u64(sb->nextalloc); // probably does not belong here
	disk->freeatom = to_be_u32(sb->freeatom); // probably does not belong here
	disk->atomgen = to_be_u32(sb->atomgen); // probably does not belong here
	disk->freeblocks = to_be_u64(sb->freeblocks); // probably does not belong here
	disk->iroot = to_be_u64((u64)sb->itable.root.depth << 48 | sb->itable.root.block);
	//hexdump(&sb->super, sizeof(sb->super));
	return diskwrite(sb->devmap->dev->fd, &sb->super, sizeof(struct disksuper), SB_LOC);
}

int sync_super(SB)
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

int make_tux3(SB, int fd)
{
	int err = 0;
	trace("create bitmap");
	if (!(sb->bitmap = new_inode(sb, TUX_BITMAP_INO)))
		goto eek;

	trace("reserve superblock");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++)
		trace("reserve %Lx", (L)balloc_from_range(sb->bitmap, i, 1)); // error ???

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
	sb->unatom_base = sb->unatom_base + (1 << (34 - sb->blockbits));
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
