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

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "hexdump.c"

#define mark_inode_dirty(x)
typedef u16 le16;

enum {DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK };
typedef int (filldir_t)(void *dirent, char *name, unsigned namelen, loff_t offset, unsigned inode, unsigned type);

#ifndef trace
#define trace trace_off
#endif

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
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
			printf("%.*s (%x:%i) ",
				entry->name_len,
				entry->name,
				entry->inum,
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

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	map_t *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	struct buffer_head *buffer;
	struct sb *sb = &(struct sb){ .super = { .volblocks = to_be_u64(150) }, .blockbits = dev->bits };
	map->inode = &(struct inode){ .i_sb = sb, .map = map, .i_mode = S_IFDIR };
	tux_create_entry(map->inode, "hello", 5, 0x666, S_IFREG);
	tux_create_entry(map->inode, "world", 5, 0x777, S_IFLNK);
	tux_dirent *entry = tux_find_entry(map->inode, "hello", 5, &buffer);
	if (entry)
		hexdump(entry, entry->name_len);
	tux_dump_entries(blockget(map, 0));

	if (!tux_delete_entry(buffer, entry)) {
		show_buffers(map);
		map->inode->i_ctime = map->inode->i_mtime = gettime();
		mark_inode_dirty(map->inode);
	}

	tux_dump_entries(blockget(map, 0));
	struct file *file = &(struct file){ .f_inode = map->inode };
	for (int i = 0; i < 10; i++) {
		char name[100];
		sprintf(name, "file%i", i);
		tux_create_entry(map->inode, name, strlen(name), 0x800 + i, S_IFREG);
	}
	tux_dump_entries(blockget(map, 0));
	char dents[10000];
	tux_readdir(file, dents, filldir);
	show_buffers(map);
	exit(0);
}
