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

#include "tux3user.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/dir.c"

void tux_dump_entries(struct buffer_head *buffer)
{
	struct inode *dir = buffer->map->inode;
	unsigned blocksize = bufsize(buffer);
	tux_dirent *entry = (tux_dirent *)bufdata(buffer);
	tux_dirent *limit = bufdata(buffer) + blocksize;

	__tux3_dbg("entries <%Lx:%Lx>: ",
		   tux_inode(dir)->inum, bufindex(buffer));
	while (entry < limit) {
		if (!entry->rec_len) {
			tux_zero_len_error(dir, bufindex(buffer));
			break;
		}
		if (!is_deleted(entry))
			__tux3_dbg("%.*s (%Lx:%i) ",
				   entry->name_len,
				   entry->name,
				   be64_to_cpu(entry->inum),
				   entry->type);
		entry = next_entry(entry);
	}
	blockput(buffer);
	__tux3_dbg("\n");
}
