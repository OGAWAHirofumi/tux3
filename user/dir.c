/* Lifted from Ext2, blush. GPLv2. Portions (c) Daniel Phillips 2008 */

/*
 *  linux/include/linux/ext2_fs.h
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "hexdump.c"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/dir.c"

void tux_dump_entries(struct buffer_head *buffer)
{
	unsigned blocksize = bufsize(buffer);
	printf("entries <%Lx:%Lx>: ", (L)buffer->map->inode->inum, (L)bufindex(buffer));
	tux_dirent *entry = (tux_dirent *)bufdata(buffer);
	tux_dirent *limit = bufdata(buffer) + blocksize;
	while (entry < limit) {
		if (!entry->rec_len) {
			warn("Zero length entry");
			break;
		}
		if (!is_deleted(entry))
			printf("%.*s (%Lx:%i) ",
			       entry->name_len,
			       entry->name,
			       (L)from_be_u64(entry->inum),
			       entry->type);
		entry = next_entry(entry);
	}
	brelse(buffer);
	printf("\n");
}

int filldir(void *entry, char *name, unsigned namelen, loff_t offset, unsigned inum, unsigned type)
{
	printf("\"%.*s\"\n", namelen, name);
	return 0;
}

#ifdef build_dir
int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	struct sb *sb = rapid_sb(dev, .super = { .volblocks = to_be_u64(150) });
	struct inode *dir = rapid_open_inode(sb, NULL, S_IFDIR);
	init_buffers(dev, 1 << 20, 0);
	struct buffer_head *buffer;
	printf("empty = %i\n", tux_dir_is_empty(dir));
	tux_create_entry(dir, "hello", 5, 0x666, S_IFREG);
	tux_create_entry(dir, "world", 5, 0x777, S_IFLNK);
	tux_dirent *entry = tux_find_entry(dir, "hello", 5, &buffer);
	assert(!IS_ERR(entry));
	hexdump(entry, entry->name_len);
	tux_dump_entries(blockget(dir->map, 0));

	if (!tux_delete_entry(buffer, entry)) {
		show_buffers(dir->map);
		dir->i_ctime = dir->i_mtime = gettime();
		mark_inode_dirty(dir);
	}

	printf("empty = %i\n", tux_dir_is_empty(dir));
	tux_dump_entries(blockget(dir->map, 0));
	struct file *file = &(struct file){ .f_inode = dir };
	for (int i = 0; i < 10; i++) {
		char name[100];
		sprintf(name, "file%i", i);
		tux_create_entry(dir, name, strlen(name), 0x800 + i, S_IFREG);
	}
	tux_dump_entries(blockget(dir->map, 0));
	char dents[10000];
	tux_readdir(file, dents, filldir);
	show_buffers(dir->map);
	exit(0);
}
#endif
