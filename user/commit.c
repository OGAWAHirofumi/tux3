/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef trace
#define trace trace_on
#endif

#define include_inode_c
#include "inode.c"
//#include "kernel/commit.c"

void replay(struct sb *sb)
{
	//char *why = "something broke";
	// To do:
	// load commit blocks into map1
	// load log blocks into map2
	// scan for all fullfills
	// walk through block:
	//   if promise bread parent, apply
	//   if alloc update bitmap
	unsigned logblocks = sb->lognext, code;
	for (sb->lognext = 0; sb->lognext < logblocks;) {
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = sb->logpos;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_ALLOC:
			case LOG_FREE:
			{
				u64 block;
				unsigned count = *data++;
				data = decode48(data, &block);
				trace("%s 0x%Lx/%x", code == LOG_ALLOC ? "set" : "clear", (L)block, count);
				update_bitmap(sb, block, count, code == LOG_ALLOC);
				break;
			}
			case LOG_UPDATE:
			{
				u64 child, parent, key;
				data = decode48(data, &child);
				data = decode48(data, &parent);
				data = decode48(data, &key);
				trace("child = 0x%Lx, parent = 0x%Lx, key = 0x%Lx", (L)child, (L)parent, (L)key);
				break;
			}
			default:
				break; //goto eek;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	struct sb *sb = &(struct sb){ RAPID_INIT_SB(dev), };
	sb->volmap = rapid_new_inode(sb, NULL, 0);
	sb->bitmap = rapid_new_inode(sb, NULL, 0);
	sb->logmap = rapid_new_inode(sb, &filemap_ops, 0);
	init_buffers(dev, 1 << 20, 0);
	for (int block = 0; block < 10; block++) {
		struct buffer_head *buffer = blockget(mapping(sb->bitmap), block);
		memset(bufdata(buffer), 0, sb->blocksize);
		set_buffer_uptodate(buffer);
	}

	log_alloc(sb, 9, 6, 1);
	log_alloc(sb, 0x99, 3, 0);
	log_update(sb, 0xbabe, 0xd00d, 0x666);
	//hexdump(sb->logbuf->data, 0x40);
	log_finish(sb);
	replay(sb);
	exit(0);
}
