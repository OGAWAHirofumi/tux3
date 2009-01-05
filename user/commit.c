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

#include "tux3.h"
#include "kernel/hexdump.c"
#include "kernel/balloc.c"

struct logblock { be_u16 magic, bytes; be_u64 prevlog; unsigned char data[]; };

enum { LOG_ALLOC, LOG_FREE };

struct commit_entry { be_u64 previous; };

void log_next(struct sb *sb)
{
	sb->logbuf = blockget(sb->logmap, sb->lognext++);
	sb->logpos = sb->logbuf->data + sizeof(struct logblock);
	sb->logtop = sb->logbuf->data + sb->blocksize;
}

void log_end(struct sb *sb)
{
	struct logblock *log = sb->logbuf->data;
	assert(sb->logtop >= sb->logpos);
	log->bytes = to_be_u16(sb->logpos - log->data);
	memset(sb->logpos, 0, sb->logtop - sb->logpos);
	brelse(sb->logbuf);
	sb->logbuf = NULL;
}

void *log_need(struct sb *sb, unsigned bytes)
{
	if (sb->logpos + bytes > sb->logtop) {
		if (sb->logbuf)
			log_end(sb);
		log_next(sb);
		*(struct logblock *)sb->logbuf->data = (struct logblock){
			.magic = to_be_u16(0xc0de) };
	}
	return sb->logpos;
}

void log_alloc(struct sb *sb, block_t block, unsigned count, unsigned alloc)
{
	unsigned char *data = log_need(sb, 8);
	*data++ = alloc ? LOG_ALLOC : LOG_FREE;
	*data++ = count;
	sb->logpos = encode48(data, block);
}

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
	u64 v64;
	unsigned logblocks = sb->lognext, code;
	for (sb->lognext = 0; sb->lognext < logblocks;) {
		log_next(sb);
		struct logblock *log = sb->logbuf->data;
		unsigned char *data = sb->logpos;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_ALLOC:
			case LOG_FREE: {
				unsigned count = *data++;
				data = decode48(data, &v64);
				trace("%s 0x%Lx/%x", code == LOG_ALLOC ? "set" : "clear", v64, count);
				update_bitmap(sb, v64, count, code == LOG_ALLOC);
				break;
			}
			default:
				;
				//goto eek;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	struct sb *sb = &(struct sb){ .logmap = new_map(dev, NULL), .blockbits = dev->bits, .blocksize = 1 << dev->bits };
	sb->bitmap = &(struct inode){ .i_sb = sb, .map = new_map(dev, NULL) },
	sb->bitmap->map->inode = sb->bitmap;
	init_buffers(dev, 1 << 20);
	for (int block = 0; block < 10; block++) {
		struct buffer_head *buffer = blockget(mapping(sb->bitmap), block);
		memset(bufdata(buffer), 0, sb->blocksize);
		set_buffer_uptodate(buffer);
	}

	log_alloc(sb, 9, 6, 1);
	log_alloc(sb, 0x99, 3, 0);
	log_end(sb);
	replay(sb);
	return 0;
}
