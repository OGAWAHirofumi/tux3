/*
 * Copyright (c) 2008, Daniel Phillips
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

static const char *log_name[] = {
#define X(x)	[x] = #x
	X(LOG_BALLOC),
	X(LOG_BFREE),
	X(LOG_BFREE_ON_ROLLUP),
	X(LOG_BFREE_RELOG),
	X(LOG_LEAF_REDIRECT),
	X(LOG_BNODE_REDIRECT),
	X(LOG_BNODE_ROOT),
	X(LOG_BNODE_SPLIT),
	X(LOG_BNODE_ADD),
	X(LOG_BNODE_UPDATE),
	X(LOG_ROLLUP),
	X(LOG_DELTA),
#undef X
};

struct replay_info {
	void *rollup_pos;	/* position of rollup log in a log block */
	block_t rollup_index;	/* index of a log block including rollup log */
	block_t blocknrs[];	/* block address of log blocks */
};

static void *find_log_rollup(struct logblock *log)
{
	unsigned char *data = log->data;

	while (data < log->data + from_be_u16(log->bytes)) {
		u8 code = *data;
		if (code == LOG_ROLLUP)
			return data;
		data += log_size[code];
	}
	return NULL;
}

/* Prepare log info for replay and pin logblocks. */
static struct replay_info *replay_prepare(struct sb *sb)
{
	block_t logchain = sb->logchain;
	unsigned j, i, logcount = from_be_u32(sb->super.logcount);
	struct replay_info *info;
	struct buffer_head *buffer;
	int err;

	/* FIXME: this address array is quick hack. Rethink about log
	 * block management and log block address. */
	info = malloc(sizeof(struct replay_info) + logcount * sizeof(block_t));
	if (!info)
		return ERR_PTR(-ENOMEM);
	info->rollup_pos = NULL;
	info->rollup_index = -1;
	memset(info->blocknrs, 0, logcount * sizeof(block_t));

	trace("load %u logblocks", logcount);
	i = logcount;
	while (i-- > 0) {
		buffer = blockget(mapping(sb->logmap), i);
		if (!buffer) {
			err = -ENOMEM;
			goto error;
		}
		assert(bufindex(buffer) == i);
		err = blockio(0, buffer, logchain);
		if (err) {
			blockput(buffer);
			goto error;
		}

		struct logblock *log = bufdata(buffer);
		if (log->magic != to_be_u16(TUX3_MAGIC_LOG)) {
			warn("bad log magic %x", from_be_u16(log->magic));
			blockput(buffer);
			err = -EINVAL;
			goto error;
		}

		/* Find latest rollup (Note: LOG_ROLLUP is first record). */
		if (info->rollup_index == -1) {
			info->rollup_pos = find_log_rollup(log);
			if (info->rollup_pos)
				info->rollup_index = bufindex(buffer);
		}
		/* Store index => blocknr map */
		info->blocknrs[bufindex(buffer)] = logchain;

		logchain = from_be_u64(log->logchain);
	}

	return info;

error:
	free(info);

	j = logcount;
	while (--j > i) {
		buffer = blockget(mapping(sb->logmap), j);
		assert(buffer != NULL);
		blockput(buffer);
		blockput(buffer);
	}
	return ERR_PTR(err);
}

/* Unpin log blocks, and prepare for future logging. */
static void replay_done(struct sb *sb, struct replay_info *info)
{
	unsigned i = from_be_u32(sb->super.logcount);

	free(info);

	while (i-- > 0) {
		struct buffer_head *buffer = blockget(mapping(sb->logmap), i);
		assert(buffer != NULL);
		blockput(buffer);
		blockput(buffer);
	}

	/* Update for future logblock position */
	sb->logthis = sb->lognext = from_be_u32(sb->super.logcount);
}

typedef int (*replay_log_func_t)(struct sb *, struct buffer_head *,
				 struct replay_info *);

/* Replay physical update like bnode, etc. */
static int replay_log_stage1(struct sb *sb, struct buffer_head *logbuf,
			     struct replay_info *info)
{
	struct logblock *log = bufdata(logbuf);
	unsigned char *data = log->data;
	int err;

	/* Check whether array is uptodate */
	BUILD_BUG_ON(ARRAY_SIZE(log_name) != LOG_TYPES);

	/* If log is before latest rollup, those were already applied to FS. */
	if (bufindex(logbuf) < info->rollup_index) {
		assert(0);	/* older logs should already be freed */
		return 0;
	}
	if (bufindex(logbuf) == info->rollup_index)
		data = info->rollup_pos;

	while (data < log->data + from_be_u16(log->bytes)) {
		u8 code = *data++;
		switch (code) {
		case LOG_BNODE_REDIRECT:
		{
			u64 oldblock, newblock;
			data = decode48(data, &oldblock);
			data = decode48(data, &newblock);
			trace("%s: oldblock %Lx, newblock %Lx",
			      log_name[code], (L)oldblock, (L)newblock);
			err = replay_bnode_redirect(sb, oldblock, newblock);
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
			if (code == LOG_BNODE_UPDATE)
				err = replay_bnode_update(sb, parent, child, key);
			if (err)
				return err;
			break;
		}
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_ROLLUP:
		case LOG_BFREE_RELOG:
		case LOG_LEAF_REDIRECT:
		case LOG_ROLLUP:
		case LOG_DELTA:
			data += log_size[code] - sizeof(code);
			break;
		default:
			warn("unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

/* Replay logical update like bitmap data pages, etc. */
static int replay_log_stage2(struct sb *sb, struct buffer_head *logbuf,
			     struct replay_info *info)
{
	struct logblock *log = bufdata(logbuf);
	block_t blocknr = info->blocknrs[bufindex(logbuf)];
	unsigned char *data = log->data;
	int err;

	/* If log is before latest rollup, those were already applied to FS. */
	if (bufindex(logbuf) < info->rollup_index) {
		assert(0);	/* older logs should already be freed */
		return 0;
	}
	if (bufindex(logbuf) == info->rollup_index)
		data = info->rollup_pos;

	/* log block address itself works as balloc log */
	trace("LOG BLOCK: logblock %Lx", (L)blocknr);
	err = replay_update_bitmap(sb, blocknr, 1, 1);
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
		case LOG_BFREE_RELOG:
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
		case LOG_LEAF_REDIRECT:
		case LOG_BNODE_REDIRECT:
		{
			u64 oldblock, newblock;
			data = decode48(data, &oldblock);
			data = decode48(data, &newblock);
			trace("%s: oldblock %Lx, newblock %Lx",
			      log_name[code], (L)oldblock, (L)newblock);
			err = replay_update_bitmap(sb, newblock, 1, 1);
			if (err)
				return err;
			if (code == LOG_LEAF_REDIRECT) {
				err = replay_update_bitmap(sb, oldblock, 1, 0);
				if (err)
					return err;
			} else {
				/* newblock is not flushing yet */
				defer_bfree(&sb->derollup, oldblock, 1);
			}
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
		case LOG_BNODE_SPLIT:
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE:
		case LOG_ROLLUP:
		case LOG_DELTA:
			data += log_size[code] - sizeof(code);
			break;
		default:
			warn("unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

static int replay_logblocks(struct sb *sb, struct replay_info *info,
			    replay_log_func_t replay_log_func)
{
	unsigned logcount = from_be_u32(sb->super.logcount);
	int err;

	for (sb->lognext = 0; sb->lognext < logcount;) {
		trace("log block %i, blocknr %Lx, rollup %Lx", sb->lognext, (L)info->blocknrs[sb->lognext], (L)info->rollup_index);
		log_next(sb);
		err = replay_log_func(sb, sb->logbuf, info);
		log_drop(sb);

		if (err)
			return err;
	}

	return 0;
}

void *replay_stage1(struct sb *sb)
{
	struct replay_info *info = replay_prepare(sb);
	if (!IS_ERR(info)) {
		int err = replay_logblocks(sb, info, replay_log_stage1);
		if (err) {
			replay_done(sb, info);
			return ERR_PTR(err);
		}
	}
	return info;
}

int replay_stage2(struct sb *sb, void *info)
{
	int err = replay_logblocks(sb, info, replay_log_stage2);
	replay_done(sb, info);
	return err;
}
