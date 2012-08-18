/*
 * Copyright (c) 2008, Daniel Phillips
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

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

static const char *log_name[LOG_TYPES] = {
#define X(x)	[x] = #x
	X(LOG_BALLOC),
	X(LOG_BFREE),
	X(LOG_BFREE_ON_ROLLUP),
	X(LOG_LEAF_REDIRECT),
	X(LOG_BNODE_REDIRECT),
	X(LOG_BNODE_ROOT),
	X(LOG_BNODE_SPLIT),
	X(LOG_BNODE_ADD),
	X(LOG_BNODE_UPDATE),
#undef X
};

static int replay_load_logblocks(struct sb *sb)
{
	block_t logchain = sb->logchain;
	unsigned logcount = from_be_u32(sb->super.logcount);

	/* Load log blocks */
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

	return 0;
}

typedef int (*replay_log_func_t)(struct sb *, struct logblock *, block_t);

/* Replay physical update like bnode, etc. */
static int replay_log_stage1(struct sb *sb, struct logblock *log, block_t blknr)
{
	unsigned char *data = log->data;
	int err;

	while (data < log->data + from_be_u16(log->bytes)) {
		u8 code = *data++;
		switch (code) {
		case LOG_LEAF_REDIRECT:
		case LOG_BNODE_REDIRECT:
		{
			u64 oldblock, newblock;
			data = decode48(data, &oldblock);
			data = decode48(data, &newblock);
			trace("%s: oldblock %Lx, newblock %Lx",
			      log_name[code], (L)oldblock, (L)newblock);
			break;
		}
		case LOG_BNODE_ROOT:
		{
			u64 root, left, right, rkey;
			u8 count;
			count = *data++;
			data = decode48(data, &root);
			data = decode48(data, &left);
			data = decode48(data, &right);
			data = decode48(data, &rkey);
			trace("%s: count %u, root block %Lx, left %Lx, right %Lx, rkey %Lx",
			      log_name[code], count, (L)root, (L)left, (L)right, (L)rkey);

			err = replay_bnode_root(sb, root, count, left, right, rkey);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_SPLIT:
		{
			u32 pos;
			u64 src, dest;
			data = decode32(data, &pos);
			data = decode48(data, &src);
			data = decode48(data, &dest);
			trace("%s: pos %x, src %Lx, dest %Lx",
			      log_name[code], pos, (L)src, (L)dest);
			break;
		}
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE:
		{
			u64 child, parent, key;
			data = decode48(data, &parent);
			data = decode48(data, &child);
			data = decode48(data, &key);
			trace("%s: parent 0x%Lx, child 0x%Lx, key 0x%Lx",
			      log_name[code], (L)parent, (L)child, (L)key);
			break;
		}
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_ROLLUP:
			data += logsize[code] - sizeof(code);
			break;
		default:
			warn("unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

/* Replay logical update like bitmap data pages, etc. */
static int replay_log_stage2(struct sb *sb, struct logblock *log, block_t blknr)
{
	unsigned char *data = log->data;
	int err;

	/* log block address itself works as balloc log */
	trace("LOG BLOCK: logblock %Lx", (L)blknr);
	err = replay_update_bitmap(sb, blknr, 1, 1);
	if (err)
		return err;
	/* FIXME: make defree entires for logblock */
	/* defer_bfree(&sb->new_decycle, blknr, 1); */

	while (data < log->data + from_be_u16(log->bytes)) {
		u8 code = *data++;
		switch (code) {
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_ROLLUP:
		{
			u64 block;
			u8 count;
			count = *data++;
			data = decode48(data, &block);
			trace("%s: count %u, block %Lx",
			      log_name[code], count, (L)block);

			err = replay_update_bitmap(sb, block, count, code == LOG_BALLOC);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_ROOT:
		{
			u64 root, left, right, rkey;
			u8 count;
			count = *data++;
			data = decode48(data, &root);
			data = decode48(data, &left);
			data = decode48(data, &right);
			data = decode48(data, &rkey);
			trace("%s: count %u, root block %Lx, left %Lx, right %Lx, rkey %Lx",
			      log_name[code], count, (L)root, (L)left, (L)right, (L)rkey);

			err = replay_update_bitmap(sb, root, 1, 1);
			if (err)
				return err;
			break;
		}
		case LOG_LEAF_REDIRECT:
		case LOG_BNODE_REDIRECT:
		case LOG_BNODE_SPLIT:
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE:
			data += logsize[code] - sizeof(code);
			break;
		default:
			warn("unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

static int replay_logblocks(struct sb *sb, replay_log_func_t replay_log_func)
{
	unsigned i, logcount = from_be_u32(sb->super.logcount);
	block_t logchain, *array;
	int err = 0;

	/* FIXME: this address array is quick hack. Rethink about log
	 * block management and log block address. */
	array = malloc(logcount * sizeof(block_t));
	if (!array)
		return -ENOMEM;

	logchain = sb->logchain;
	i = logcount;
	while (i--) {
		array[i] = logchain;

		struct buffer_head *buffer = blockget(mapping(sb->logmap), i);
		if (!buffer) {
			err = -ENOMEM;
			goto out;
		}
		struct logblock *log = bufdata(buffer);
		logchain = from_be_u64(log->logchain);
		blockput(buffer);
	}

	for (sb->lognext = 0; sb->lognext < logcount;) {
		block_t blocknr = array[sb->lognext];
		trace("log block %i, blocknr %Lx", sb->lognext, (L)blocknr);
		log_next(sb);
		err = replay_log_func(sb, bufdata(sb->logbuf), blocknr);
		log_drop(sb);

		if (err)
			break;
	}

out:
	free(array);

	return err;
}

int replay_stage1(struct sb *sb)
{
	int err;

	err = replay_load_logblocks(sb);
	if (err)
		return err;

	return replay_logblocks(sb, replay_log_stage1);
}

int replay_stage2(struct sb *sb)
{
	return replay_logblocks(sb, replay_log_stage2);
}
