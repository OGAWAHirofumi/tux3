/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef TUX3_WALK_C
#define TUX3_WALK_C

#include "tux3user.h"

/* walk has to access internal structure */
#include "kernel/btree.c"
#include "kernel/dleaf.c"
#include "kernel/dleaf2.c"
#include "kernel/ileaf.c"

struct walk_btree_ops {
	void (*pre)(struct btree *, void *);
	void (*bnode)(struct btree *, struct buffer_head *, int, void *);
	void (*leaf)(struct btree *, struct buffer_head *, void *);
	void (*post)(struct btree *, void *);
};

struct walk_logchain_ops {
	void (*pre)(struct sb *, struct buffer_head *, unsigned, int, void *);
	void (*log)(struct sb *, struct buffer_head *, u8, u8 *, unsigned,
		    int, void *);
	void (*post)(struct sb *, struct buffer_head *, unsigned, int, void *);
};

typedef void (*walk_ileaf_cb)(struct buffer_head *, int, struct inode *,
			      void *);
typedef void (*walk_dleaf_cb)(struct btree *, struct buffer_head *,
			      block_t, block_t, unsigned, void *);

static void walk_dleaf1(struct btree *btree, struct buffer_head *leafbuf,
			walk_dleaf_cb callback, void *data)
{
	struct sb *sb = btree->sb;
	struct dleaf *dleaf = bufdata(leafbuf);
	struct dwalk walk;

	if (dwalk_probe(dleaf, sb->blocksize, &walk, 0)) {
		do {
			block_t index = dwalk_index(&walk);
			block_t block = dwalk_block(&walk);
			unsigned count = dwalk_count(&walk);

			callback(btree, leafbuf, index, block, count, data);
		} while (dwalk_next(&walk));
	}
}

static void walk_dleaf2(struct btree *btree, struct buffer_head *leafbuf,
			walk_dleaf_cb callback, void *data)
{
	struct dleaf2 *dleaf = bufdata(leafbuf);
	struct diskextent2 *dex, *dex_limit;
	struct extent prev = { .logical = TUXKEY_LIMIT, };

	dex = dleaf->table;
	dex_limit = dex + be16_to_cpu(dleaf->count);
	while (dex < dex_limit) {
		struct extent ex;
		get_extent(dex, &ex);

		if (prev.logical != TUXKEY_LIMIT) {
			unsigned count = ex.logical - prev.logical;
			if (prev.physical) {
				callback(btree, leafbuf, prev.logical,
					 prev.physical, count, data);
			}
		}

		prev = ex;
		dex++;
	}
}

static void walk_dleaf(struct btree *btree, struct buffer_head *leafbuf,
		       walk_dleaf_cb callback, void *data)
{
	struct dleaf *dleaf = bufdata(leafbuf);

	if (dleaf->magic == cpu_to_be16(TUX3_MAGIC_DLEAF))
		walk_dleaf1(btree, leafbuf, callback, data);
	else
		walk_dleaf2(btree, leafbuf, callback, data);
}

static inline u16 ileaf_attr_size(__be16 *dict, int at)
{
	int size = __atdict(dict, at + 1) - atdict(dict, at);
	assert(size >= 0);
	return size;
}

static void walk_ileaf(struct btree *btree, struct buffer_head *leafbuf,
		       walk_ileaf_cb callback, void *data)
{
	struct ileaf *ileaf = bufdata(leafbuf);
	__be16 *dict = ileaf_dict(btree, ileaf);
	int at;

	/* walk inode's dtree */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		inum_t inum = ibase(ileaf) + at;
		struct inode *inode = tux3_iget(btree->sb, inum);
		if (IS_ERR(inode)) {
			tux3_fs_error(btree->sb,
				      "inode couldn't get: inum %Lu: %ld",
				      inum, PTR_ERR(inode));
		}

		callback(leafbuf, at, inode, data);

		iput(inode);
	}
}

static void walk_btree(struct btree *btree, struct walk_btree_ops *cb,
		       void *data)
{
	struct cursor *cursor;
	struct buffer_head *buffer;
	int err;

	if (!has_root(btree))
		return;

	if (cb->pre)
		cb->pre(btree, data);

	cursor = alloc_cursor(btree, 0);
	if (!cursor)
		strerror_exit(1, ENOMEM, "out of memory");

	err = cursor_read_root(cursor);
	if (err) {
		tux3_err(btree->sb, "cursor_read_root(): %d", err);
		goto error;
	}

	buffer = cursor->path[cursor->level].buffer;
	if (cb->bnode)
		cb->bnode(btree, buffer, cursor->level, data);

	while (1) {
		int ret = cursor_advance_down(cursor);
		if (ret < 0) {
			tux3_err(btree->sb, "cursor_advance_down() : %d", ret);
			goto error;
		}
		if (ret) {
			buffer = cursor->path[cursor->level].buffer;
			if (cb->bnode)
				cb->bnode(btree, buffer, cursor->level, data);
			continue;
		}

		buffer = cursor_leafbuf(cursor);
		if (cb->leaf)
			cb->leaf(btree, buffer, data);

		do {
			if (!cursor_advance_up(cursor))
				goto out;
		} while (cursor_level_finished(cursor));
	}

out:
	if (cb->post)
		cb->post(btree, data);

	free_cursor(cursor);

	return;

error:
	release_cursor(cursor);
	free_cursor(cursor);
}

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

static void walk_logchain(struct sb *sb, struct walk_logchain_ops *cb,
			  void *data)
{
	struct buffer_head *buffer;
	block_t nextchain;
	unsigned logcount;
	int obsolete = 0;

	/* Check whether array is uptodate */
	BUILD_BUG_ON(ARRAY_SIZE(log_name) != LOG_TYPES);

	nextchain = be64_to_cpu(sb->super.logchain);
	logcount = be32_to_cpu(sb->super.logcount);
	while (logcount > 0) {
		struct logblock *log;
		u8 *rollup_pos = NULL;
		int obsolete_block = obsolete;

		buffer = vol_bread(sb, nextchain);
		assert(buffer);

		log = bufdata(buffer);

		/* Find LOG_ROLLUP */
		if (!obsolete_block) {
			u8 *p = log->data;
			while (p < log->data + be16_to_cpu(log->bytes)) {
				u8 code = *p;

				if (code == LOG_ROLLUP) {
					rollup_pos = p;
					obsolete = 1;
					break;
				}

				p += log_size[code];
			}
		}

		if (cb->pre)
			cb->pre(sb, buffer, logcount, obsolete_block, data);

		if (cb->log) {
			int obsolete_log = obsolete_block;
			u8 *p = log->data;
			while (p < log->data + be16_to_cpu(log->bytes)) {
				u8 code = *p;
				unsigned len = log_size[code];

				if (rollup_pos) {
					if (p < rollup_pos)
						obsolete_log = 1;
					else
						obsolete_log = 0;
				}

				cb->log(sb, buffer, code, p + sizeof(code),
					len, obsolete_log, data);

				p += len;
			}
		}

		if (cb->post)
			cb->post(sb, buffer, logcount, obsolete_block, data);

		logcount--;

		nextchain = be64_to_cpu(log->logchain);
		blockput(buffer);
	}
}

void *unuse_walk_logchain = walk_logchain;	/* fsck doesn't use this */
void *unuse_walk_dleaf = walk_dleaf;		/* graph doesn't use this */

#endif /* !TUX3_WALK_C */
