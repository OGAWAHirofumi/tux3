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
	X(LOG_BFREE_ON_UNIFY),
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
	X(LOG_UNIFY),
	X(LOG_DELTA),
#undef X
};

static struct replay *alloc_replay(struct sb *sb, unsigned logcount)
{
	struct replay *rp;

	rp = malloc(sizeof(*rp) + logcount * sizeof(block_t));
	if (!rp)
		return ERR_PTR(-ENOMEM);

	rp->sb = sb;
	rp->unify_pos = NULL;
	rp->unify_index = -1;
	memset(rp->blocknrs, 0, logcount * sizeof(block_t));

	INIT_LIST_HEAD(&rp->log_orphan_add);
	INIT_LIST_HEAD(&rp->orphan_in_otree);

	return rp;
}

static void free_replay(struct replay *rp)
{
	assert(list_empty(&rp->log_orphan_add));
	assert(list_empty(&rp->orphan_in_otree));
	free(rp);
}

static int replay_check_log(struct replay *rp, struct buffer_head *logbuf)
{
	struct sb *sb = rp->sb;
	struct logblock *log = bufdata(logbuf);
	unsigned char *data = log->data;

	if (log->magic != cpu_to_be16(TUX3_MAGIC_LOG)) {
		tux3_err(sb, "bad log magic %x", be16_to_cpu(log->magic));
		return -EINVAL;
	}
	if (be16_to_cpu(log->bytes) + sizeof(*log) > sb->blocksize) {
		tux3_err(sb, "log bytes is too big");
		return -EINVAL;
	}

	while (data < log->data + be16_to_cpu(log->bytes)) {
		u8 code = *data;

		/* Find latest unify. */
		if (code == LOG_UNIFY && rp->unify_index == -1) {
			rp->unify_pos = data;
			/* FIXME: index is unnecessary to use. We just
			 * want to know whether before or after unify
			 * mark. */
			rp->unify_index = bufindex(logbuf);
		}

		if (log_size[code] == 0) {
			tux3_err(sb, "invalid log code: 0x%02x", code);
			return -EINVAL;
		}
		data += log_size[code];
	}

	return 0;
}

/* Unpin logblocks. */
static void replay_unpin_logblocks(struct sb *sb, unsigned i, unsigned logcount)
{
	struct buffer_head *logbuf;

	while (i < logcount) {
		logbuf = blockget(mapping(sb->logmap), i);
		assert(logbuf != NULL);
		blockput(logbuf);
		blockput(logbuf);	/* Unpin */

		i++;
	}
}

/* Prepare log info for replay and pin logblocks. */
static struct replay *replay_prepare(struct sb *sb)
{
	block_t logchain = be64_to_cpu(sb->super.logchain);
	unsigned i, logcount = be32_to_cpu(sb->super.logcount);
	struct replay *rp;
	struct buffer_head *buffer;
	int err;

	/* FIXME: this address array is quick hack. Rethink about log
	 * block management and log block address. */
	rp = alloc_replay(sb, logcount);
	if (IS_ERR(rp))
		return rp;

	/* FIXME: maybe, we should use bufvec to read log blocks */
	trace("load %u logblocks", logcount);
	i = logcount;
	while (i-- > 0) {
		struct logblock *log;

		buffer = blockget(mapping(sb->logmap), i);
		if (!buffer) {
			i++;
			err = -ENOMEM;
			goto error;
		}
		assert(bufindex(buffer) == i);
		err = blockio(READ, sb, buffer, logchain);
		if (err)
			goto error;

		err = replay_check_log(rp, buffer);
		if (err)
			goto error;

		/* Store index => blocknr map */
		rp->blocknrs[bufindex(buffer)] = logchain;

		log = bufdata(buffer);
		logchain = be64_to_cpu(log->logchain);
	}

	return rp;

error:
	free_replay(rp);
	replay_unpin_logblocks(sb, i, logcount);

	return ERR_PTR(err);
}

/* Unpin log blocks, and prepare for future logging. */
static void replay_done(struct replay *rp)
{
	struct sb *sb = rp->sb;

	clean_orphan_list(&rp->log_orphan_add);	/* for error path */
	free_replay(rp);

	sb->lognext = be32_to_cpu(sb->super.logcount);
	replay_unpin_logblocks(sb, 0, sb->lognext);
	log_finish_cycle(sb, 0);
}

typedef int (*replay_log_t)(struct replay *, struct buffer_head *);

static int replay_log_stage1(struct replay *rp, struct buffer_head *logbuf)
{
	struct sb *sb = rp->sb;
	struct logblock *log = bufdata(logbuf);
	unsigned char *data = log->data;
	int err;

	/* Check whether array is uptodate */
	BUILD_BUG_ON(ARRAY_SIZE(log_name) != LOG_TYPES);

	/* If log is before latest unify, those were already applied to FS. */
	if (bufindex(logbuf) < rp->unify_index) {
//		assert(0);	/* older logs should already be freed */
		return 0;
	}
	if (bufindex(logbuf) == rp->unify_index)
		data = rp->unify_pos;

	while (data < log->data + be16_to_cpu(log->bytes)) {
		u8 code = *data++;
		switch (code) {
		case LOG_BNODE_REDIRECT:
		{
			u64 oldblock, newblock;
			data = decode48(data, &oldblock);
			data = decode48(data, &newblock);
			trace("%s: oldblock %Lx, newblock %Lx",
			      log_name[code], oldblock, newblock);
			err = replay_bnode_redirect(rp, oldblock, newblock);
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
			      log_name[code], count, root, left, right, rkey);

			err = replay_bnode_root(rp, root, count, left, right, rkey);
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
			      log_name[code], pos, src, dst);
			err = replay_bnode_split(rp, src, pos, dst);
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
			      log_name[code], parent, child, key);
			if (code == LOG_BNODE_UPDATE)
				err = replay_bnode_update(rp, parent, child, key);
			else
				err = replay_bnode_add(rp, parent, child, key);
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
			      log_name[code], src, dst);
			err = replay_bnode_merge(rp, src, dst);
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
			      log_name[code], bnode, count, key);
			err = replay_bnode_del(rp, bnode, key, count);
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
			      log_name[code], bnode, from, to);
			err = replay_bnode_adjust(rp, bnode, from, to);
			if (err)
				return err;
			break;
		}
		case LOG_BNODE_FREE:
		{
			u64 block;
			data = decode48(data, &block);
			trace("%s: block %Lx", log_name[code], block);
			blockput_free_unify(sb, vol_find_get_block(sb, block));
			break;
		}
		case LOG_FREEBLOCKS:
		{
			u64 freeblocks;
			data = decode48(data, &freeblocks);
			trace("%s: freeblocks %llu", log_name[code],
			      freeblocks);
			sb->freeblocks = freeblocks;
			break;
		}
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_UNIFY:
		case LOG_BFREE_RELOG:
		case LOG_LEAF_REDIRECT:
		case LOG_LEAF_FREE:
		case LOG_ORPHAN_ADD:
		case LOG_ORPHAN_DEL:
		case LOG_UNIFY:
		case LOG_DELTA:
			data += log_size[code] - sizeof(code);
			break;
		default:
			tux3_err(rp->sb, "unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

static int replay_log_stage2(struct replay *rp, struct buffer_head *logbuf)
{
	struct sb *sb = rp->sb;
	struct logblock *log = bufdata(logbuf);
	unsigned char *data = log->data;
	int err;

	/* If log is before latest unify, those were already applied to FS. */
	if (bufindex(logbuf) < rp->unify_index) {
//		assert(0);	/* older logs should already be freed */
		return 0;
	}
	if (bufindex(logbuf) == rp->unify_index)
		data = rp->unify_pos;

	while (data < log->data + be16_to_cpu(log->bytes)) {
		u8 code = *data++;
		switch (code) {
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_UNIFY:
		case LOG_BFREE_RELOG:
		{
			u64 block;
			u32 count;
			data = decode32(data, &count);
			data = decode48(data, &block);
			trace("%s: count %u, block %Lx",
			      log_name[code], count, block);

			err = 0;
			if (code == LOG_BALLOC)
				err = replay_update_bitmap(rp, block, count, 1);
			else if (code == LOG_BFREE_ON_UNIFY)
				defer_bfree(sb, &sb->deunify, block, count);
			else
				err = replay_update_bitmap(rp, block, count, 0);
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
			      log_name[code], oldblock, newblock);
			err = replay_update_bitmap(rp, newblock, 1, 1);
			if (err)
				return err;
			if (code == LOG_LEAF_REDIRECT) {
				err = replay_update_bitmap(rp, oldblock, 1, 0);
				if (err)
					return err;
			} else {
				/* newblock is not flushing yet */
				defer_bfree(sb, &sb->deunify, oldblock, 1);
			}
			break;
		}
		case LOG_LEAF_FREE:
		case LOG_BNODE_FREE:
		{
			u64 block;
			data = decode48(data, &block);
			trace("%s: block %Lx", log_name[code], block);
			err = replay_update_bitmap(rp, block, 1, 0);
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
			      log_name[code], count, root, left, right, rkey);

			err = replay_update_bitmap(rp, root, 1, 1);
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
			      log_name[code], pos, src, dst);
			err = replay_update_bitmap(rp, dst, 1, 1);
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
			      log_name[code], src, dst);
			err = replay_update_bitmap(rp, src, 1, 0);
			if (err)
				return err;
			break;
		}
		case LOG_ORPHAN_ADD:
		case LOG_ORPHAN_DEL:
		{
			unsigned version;
			u64 inum;
			data = decode16(data, &version);
			data = decode48(data, &inum);
			trace("%s: version 0x%x, inum 0x%Lx",
			      log_name[code], version, inum);
			if (code == LOG_ORPHAN_ADD)
				err = replay_orphan_add(rp, version, inum);
			else
				err = replay_orphan_del(rp, version, inum);
			if (err)
				return err;
			break;
		}
		case LOG_FREEBLOCKS:
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE:
		case LOG_BNODE_DEL:
		case LOG_BNODE_ADJUST:
		case LOG_UNIFY:
		case LOG_DELTA:
			data += log_size[code] - sizeof(code);
			break;
		default:
			tux3_err(sb, "unrecognized log code 0x%x", code);
			return -EINVAL;
		}
	}

	return 0;
}

static int replay_logblock_mark(struct replay *rp, struct buffer_head *logbuf)
{
	struct sb *sb = rp->sb;
	block_t blocknr = rp->blocknrs[bufindex(logbuf)];
	int err;

	/*
	 * Log block address itself works as balloc log, and adjust
	 * bitmap and deunify even if logblocks is before latest
	 * unify, to prevent to be overwritten. (This must be after
	 * LOG_FREEBLOCKS replay if there is it.)
	 *
	 * Update bitmap after logical update replay, because this
	 * logblock address can be freed while replaying.
	 */
	trace("LOG BLOCK: logblock %Lx", blocknr);
	err = replay_update_bitmap(rp, blocknr, 1, 1);
	if (err)
		return err;
	/* Mark log block as deunify block */
	defer_bfree(sb, &sb->deunify, blocknr, 1);

	return 0;
}

static int replay_logblocks(struct replay *rp, replay_log_t replay_log_func)
{
	struct sb *sb = rp->sb;
	unsigned logcount = be32_to_cpu(sb->super.logcount);
	int err;

	sb->lognext = 0;
	while (sb->lognext < logcount) {
		trace("log block %i, blocknr %Lx, unify %Lx", sb->lognext, rp->blocknrs[sb->lognext], rp->unify_index);
		log_next(sb);
		err = replay_log_func(rp, sb->logbuf);
		log_drop(sb);

		if (err)
			return err;
	}

	return 0;
}

/* Replay physical update like bnode, buffer state, etc. */
struct replay *replay_stage1(struct sb *sb)
{
	struct replay *rp = replay_prepare(sb);
	if (!IS_ERR(rp)) {
		int err = replay_logblocks(rp, replay_log_stage1);
		if (err) {
			replay_done(rp);
			return ERR_PTR(err);
		}
	}
	return rp;
}

/* Replay logical update like bitmap data pages, etc. */
int replay_stage2(struct replay *rp)
{
	int err = replay_logblocks(rp, replay_log_stage2);
	if (err)
		goto error;

	err = replay_logblocks(rp, replay_logblock_mark);
	if (err)
		goto error;

	/*
	 * Load orphan inodes into sb->orphan_add to decide what to do
	 * by caller.
	 */
	err = replay_load_orphan_inodes(rp);
	if (err)
		goto error;

	return 0;

error:
	replay_done(rp);

	return err;
}

/*
 * Replay pending frontend request like orphan, etc. I.e. this starts
 * to modify FS.
 */
int replay_stage3(struct replay *rp, int apply)
{
	struct sb *sb = rp->sb;
	LIST_HEAD(orphan_in_otree);

	list_splice_init(&rp->orphan_in_otree, &orphan_in_otree);
	replay_done(rp);
	/* Start logging after replay_done() */

	replay_iput_orphan_inodes(sb, &orphan_in_otree, apply);

	return 0;
}
