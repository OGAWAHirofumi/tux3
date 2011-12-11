/*
 * Copyright (c) 2008, Daniel Phillips
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
	return devio(rw, sb_dev(sb), block << sb->blockbits, bufdata(buffer), sb->blocksize);
}

static unsigned logsize[LOG_TYPES] = {
	[LOG_BALLOC] = 8,
	[LOG_BFREE] = 8,
	[LOG_BFREE_ON_ROLLUP] = 8,
	[LOG_LEAF_REDIRECT] = 13,
	[LOG_BNODE_REDIRECT] = 13,
	[LOG_BNODE_ROOT] = 26,
	[LOG_BNODE_SPLIT] = 15,
	[LOG_BNODE_ADD] = 19,
	[LOG_BNODE_UPDATE] = 19,
};

int replay(struct sb *sb)
{
	block_t logchain = sb->logchain;
	unsigned logcount = from_be_u32(sb->super.logcount);

	trace("load %u logblocks", logcount);
	for (int i = logcount; i-- > 0;) {
		struct buffer_head *buffer = blockget(mapping(sb->logmap), i);
		if (!buffer)
			return -ENOMEM;
		int err = blockio(0, buffer, logchain);
		if (err) {
			blockput(buffer);
			return err;
		}
		struct logblock *log = bufdata(buffer);
		if (log->magic != to_be_u16(TUX3_MAGIC_LOG)) {
			warn("bad log magic %x", from_be_u16(log->magic));
			blockput(buffer);
			return -EINVAL;
		}
		logchain = from_be_u64(log->logchain);
		blockput(buffer);
	}

	unsigned code;
	for (sb->lognext = 0; sb->lognext < logcount;) {
		trace("log block %i", sb->lognext);
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = log->data;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_BNODE_ADD:
			case LOG_BNODE_UPDATE:
			{
				u64 child, parent, key;
				data = decode48(data, &parent);
				data = decode48(data, &child);
				data = decode48(data, &key);
				trace("parent = 0x%Lx, child = 0x%Lx, key = 0x%Lx", (L)parent, (L)child, (L)key);
				break;
			}
			case LOG_BALLOC:
			case LOG_BFREE:
			case LOG_BFREE_ON_ROLLUP:
				data += logsize[code] - 1;
				break;
			case LOG_LEAF_REDIRECT:
			case LOG_BNODE_REDIRECT:
			case LOG_BNODE_ROOT:
			case LOG_BNODE_SPLIT:
			default:
				goto unknown;
			}
		}
		log_drop(sb);
	}

	for (sb->lognext = 0; sb->lognext < logcount;) {
		trace("log block %i", sb->lognext);
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = log->data;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_BALLOC:
			case LOG_BFREE:
			case LOG_BFREE_ON_ROLLUP:
			{
				u64 block;
				unsigned count = *data++;
				data = decode48(data, &block);
				trace("%s bits 0x%Lx/%x", code == LOG_BALLOC ? "set" : "clear", (L)block, count);
				int err = update_bitmap(sb, block, count, code == LOG_BALLOC);
				warn(">>> bitmap err = %i", err);
				break;
			}
			case LOG_LEAF_REDIRECT:
			case LOG_BNODE_REDIRECT:
			case LOG_BNODE_ROOT:
			case LOG_BNODE_SPLIT:
			case LOG_BNODE_ADD:
			case LOG_BNODE_UPDATE:
				data += logsize[code] - 1;
				break;
			default:
				goto unknown;
			}
		}
		log_drop(sb);
	}

	return 0;
unknown:
	warn("unrecognized log code 0x%x, 0x%x", code, LOG_BNODE_UPDATE);
	log_drop(sb);
	return -EINVAL;
}
