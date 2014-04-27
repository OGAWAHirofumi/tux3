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
#include "kernel/ileaf.c"


typedef void (*walk_data_cb)(struct btree *, struct buffer_head *,
			     struct buffer_head *, block_t,
			     void *, void *);

static void walk_extent(struct btree *btree, struct buffer_head *dleafbuf,
			block_t index, block_t block, unsigned count,
			walk_data_cb walk_data,
			void *callback, void *data)
{
	struct buffer_head *buffer;

	for (unsigned i = 0; i < count; i++) {
		buffer = blockread(mapping(btree_inode(btree)), index + i);
		assert(buffer);

		walk_data(btree, dleafbuf, buffer, block + i, callback, data);

		blockput(buffer);
	}
}

#include "walk_dir.c"

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

struct walk_dleaf_ops {
	/* callback for data extent */
	void (*extent)(struct btree *, struct buffer_head *,
		       block_t, block_t, unsigned, void *);
	/* callback for dleaf entry */
	void (*entry)(struct btree *, struct buffer_head *, unsigned,
		      unsigned, block_t, block_t, int, void *);
};

static void walk_dleaf(struct btree *btree, struct buffer_head *dleafbuf,
			struct walk_dleaf_ops *cb, void *data)
{
	struct dleaf *dleaf = bufdata(dleafbuf);
	struct diskextent2 *dex, *dex_limit;
	struct extent prev = { .logical = TUXKEY_LIMIT, };
	unsigned count = 0;

	dex = dleaf->table;
	dex_limit = dex + be16_to_cpu(dleaf->count);
	while (dex < dex_limit) {
		struct extent ex;
		get_extent(dex, &ex);

		if (prev.logical != TUXKEY_LIMIT) {
			count = ex.logical - prev.logical;
			if (prev.physical) {
				if (cb->extent)
					cb->extent(btree, dleafbuf,
						   prev.logical, prev.physical,
						   count, data);
			}
		}

		if (cb->entry) {
			int is_sentinel = dex == dex_limit - 1;
			cb->entry(btree, dleafbuf, count,
				  ex.version, ex.logical, ex.physical,
				  is_sentinel,
				  data);
		}

		prev = ex;
		dex++;
	}
}

static inline u16 ileaf_attr_size(__be16 *dict, int at)
{
	int size = __atdict(dict, at + 1) - atdict(dict, at);
	assert(size >= 0);
	return size;
}

static void walk_ileaf(struct btree *btree, struct buffer_head *ileafbuf,
		       walk_ileaf_cb callback, void *data)
{
	struct ileaf *ileaf = bufdata(ileafbuf);
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

		callback(ileafbuf, at, inode, data);

		iput(inode);
	}
}

static void walk_btree(struct btree *btree, struct walk_btree_ops *cb,
		       void *data)
{
	struct cursor *cursor;
	struct buffer_head *buffer;
	int ret;

	if (!has_root(btree))
		return;

	if (cb->pre)
		cb->pre(btree, data);

	cursor = alloc_cursor(btree, 0);
	if (!cursor)
		strerror_exit(1, ENOMEM, "out of memory");

	ret = cursor_read_root(cursor);
	if (ret < 0) {
		tux3_err(btree->sb, "cursor_read_root(): %d", ret);
		goto error;
	}

	while (1) {
		if (ret) {
			buffer = cursor->path[cursor->level].buffer;
			if (cb->bnode)
				cb->bnode(btree, buffer, cursor->level, data);
		} else {
			buffer = cursor_leafbuf(cursor);
			if (cb->leaf)
				cb->leaf(btree, buffer, data);

			do {
				if (!cursor_advance_up(cursor))
					goto out;
			} while (cursor_level_finished(cursor));
		}

		ret = cursor_advance_down(cursor);
		if (ret < 0) {
			tux3_err(btree->sb, "cursor_advance_down() : %d", ret);
			goto error;
		}
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
		u8 *unify_pos = NULL;
		int obsolete_block = obsolete;

		buffer = vol_bread(sb, nextchain);
		assert(buffer);

		log = bufdata(buffer);

		/* Find LOG_UNIFY */
		if (!obsolete_block) {
			u8 *p = log->data;
			while (p < log->data + be16_to_cpu(log->bytes)) {
				u8 code = *p;

				if (code == LOG_UNIFY) {
					unify_pos = p;
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

				if (unify_pos) {
					if (p < unify_pos)
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

#endif /* !TUX3_WALK_C */
