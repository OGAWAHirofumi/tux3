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
	X(LOG_LEAF_FREE),
	X(LOG_BNODE_REDIRECT),
	X(LOG_BNODE_ROOT),
	X(LOG_BNODE_SPLIT),
	X(LOG_BNODE_ADD),
	X(LOG_BNODE_UPDATE),
	X(LOG_BNODE_MERGE),
	X(LOG_BNODE_DEL),
	X(LOG_BNODE_ADJUST),
	X(LOG_BNODE_FREE),
	X(LOG_ORPHAN_ADD),
	X(LOG_ORPHAN_DEL),
	X(LOG_FREEBLOCKS),
	X(LOG_ROLLUP),
	X(LOG_DELTA),
#undef X
};

struct replay_info {
	void *rollup_pos;	/* position of rollup log in a log block */
	block_t rollup_index;	/* index of a log block including rollup log */
	block_t blocknrs[];	/* block address of log blocks */
};

static int replay_check_log(struct sb *sb, struct buffer_head *logbuf,
			    struct replay_info *info)
{
	struct logblock *log = bufdata(logbuf);
	unsigned char *data = log->data;

	if (log->magic != to_be_u16(TUX3_MAGIC_LOG)) {
		warn("bad log magic %x", from_be_u16(log->magic));
		return -EINVAL;
	}
	if (from_be_u16(log->bytes) + sizeof(*log) > sb->blocksize) {
		warn("log bytes is too big");
		return -EINVAL;
	}

	while (data < log->data + from_be_u16(log->bytes)) {
		u8 code = *data;

		/* Find latest rollup. */
		if (code == LOG_ROLLUP && info->rollup_index == -1) {
			info->rollup_pos = data;
			info->rollup_index = bufindex(logbuf);
		}

		if (log_size[code] == 0) {
			warn("invalid log code: 0x%02x", code);
			return -EINVAL;
		}
		data += log_size[code];
	}

	return 0;
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
		struct logblock *log;

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

		err = replay_check_log(sb, buffer, info);
		if (err) {
			blockput(buffer);
			goto error;
		}

		/* Store index => blocknr map */
		info->blocknrs[bufindex(buffer)] = logchain;

		log = bufdata(buffer);
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
	free(info);
	sb->lognext = from_be_u32(sb->super.logcount);
	log_finish_cycle(sb);
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
//		assert(0);	/* older logs should already be freed */
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
			unsigned pos;
			u64 src, dst;
			data = decode16(data, &pos);
			data = decode48(data, &src);
			data = decode48(data, &dst);
			trace("%s: pos %x, src %Lx, dst %Lx",
			      log_name[code], pos, (L)src, (L)dst);
			err = replay_bnode_split(sb, src, pos, dst);
			if (err)
				return err;
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
			else
				err = replay_bnode_add(sb, parent, child, key);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_MERGE:
		{
			u64 src, dst;
			data = decode48(data, &src);
			data = decode48(data, &dst);
			trace("%s: src 0x%Lx, dst 0x%Lx",
			      log_name[code], (L)src, (L)dst);
			err = replay_bnode_merge(sb, src, dst);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_DEL:
		{
			unsigned count;
			u64 bnode, key;
			data = decode16(data, &count);
			data = decode48(data, &bnode);
			data = decode48(data, &key);
			trace("%s: bnode 0x%Lx, count 0x%x, key 0x%Lx",
			      log_name[code], (L)bnode, count, (L)key);
			err = replay_bnode_del(sb, bnode, key, count);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_ADJUST:
		{
			u64 bnode, from, to;
			data = decode48(data, &bnode);
			data = decode48(data, &from);
			data = decode48(data, &to);
			trace("%s: bnode 0x%Lx, from 0x%Lx, to 0x%Lx",
			      log_name[code], (L)bnode, (L)from, (L)to);
			err = replay_bnode_adjust(sb, bnode, from, to);
			if (err)
				return err;
			break;
		}
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_ROLLUP:
		case LOG_BFREE_RELOG:
		case LOG_LEAF_REDIRECT:
		case LOG_LEAF_FREE:
		case LOG_BNODE_FREE:
		case LOG_ORPHAN_ADD:
		case LOG_ORPHAN_DEL:
		case LOG_FREEBLOCKS:
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
//		assert(0);	/* older logs should already be freed */
		return 0;
	}
	if (bufindex(logbuf) == info->rollup_index)
		data = info->rollup_pos;

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

			err = 0;
			if (code == LOG_BALLOC)
				err = replay_update_bitmap(sb, block, count, 1);
			else if (code == LOG_BFREE_ON_ROLLUP)
				defer_bfree(&sb->derollup, block, count);
			else
				err = replay_update_bitmap(sb, block, count, 0);
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
		case LOG_LEAF_FREE:
		case LOG_BNODE_FREE:
		{
			u64 block;
			data = decode48(data, &block);
			trace("%s: block %Lx", log_name[code], (L)block);
			err = replay_update_bitmap(sb, block, 1, 0);
			if (err)
				return err;

			if (code == LOG_BNODE_FREE)
				blockput_free(vol_find_get_block(sb, block));
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
		{
			unsigned pos;
			u64 src, dst;
			data = decode16(data, &pos);
			data = decode48(data, &src);
			data = decode48(data, &dst);
			trace("%s: pos %x, src %Lx, dst %Lx",
			      log_name[code], pos, (L)src, (L)dst);
			err = replay_update_bitmap(sb, dst, 1, 1);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_MERGE:
		{
			u64 src, dst;
			data = decode48(data, &src);
			data = decode48(data, &dst);
			trace("%s: src 0x%Lx, dst 0x%Lx",
			      log_name[code], (L)src, (L)dst);
			err = replay_update_bitmap(sb, src, 1, 0);
			if (err)
				return err;

			blockput_free(vol_find_get_block(sb, src));
			break;
		}
		case LOG_FREEBLOCKS:
		{
			u64 freeblocks;
			data = decode48(data, &freeblocks);
			trace("%s: freeblocks %llu", log_name[code],
			      (L)freeblocks);
			sb->freeblocks = freeblocks;
			break;
		}
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE:
		case LOG_BNODE_DEL:
		case LOG_BNODE_ADJUST:
		case LOG_ORPHAN_ADD:
		case LOG_ORPHAN_DEL:
		case LOG_ROLLUP:
		case LOG_DELTA:
			data += log_size[code] - sizeof(code);
			break;
		default:
			warn("unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	/*
	 * Log block address itself works as balloc log. (This must be
	 * after LOG_FREEBLOCKS replay if there is it.)
	 */
	trace("LOG BLOCK: logblock %Lx", (L)blocknr);
	err = replay_update_bitmap(sb, blocknr, 1, 1);
	if (err)
		return err;
	/* Mark log block as derollup block */
	defer_bfree(&sb->derollup, blocknr, 1);

	return 0;
}

static int replay_logblocks(struct sb *sb, struct replay_info *info,
			    replay_log_func_t replay_log_func)
{
	unsigned logcount = from_be_u32(sb->super.logcount);
	int err;

	sb->lognext = 0;
	while (sb->lognext < logcount) {
		trace("log block %i, blocknr %Lx, rollup %Lx", sb->lognext, (L)info->blocknrs[sb->lognext], (L)info->rollup_index);
		log_next(sb, 0);
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
