/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"
#include <getopt.h>

#include "walk.c"

static int opt_stats = 1;

struct stats_seek {
	block_t blocks;				/* total seek blocks */
	block_t nr;				/* number of seek */
	block_t io;				/* number of I/O */
};

struct stats_btree_block {
	block_t blocks;				/* number of blocks */
	block_t empty;				/* number of empty blocks */
	block_t bytes;				/* number of used bytes */
};

struct stats_btree_data {
	block_t blocks;				/* number of blocks */
	block_t nr;				/* number of extents */
	unsigned max;				/* maximum extent */
	unsigned min;				/* minimum extent */
	block_t last;				/* last seek pos of data */
	struct stats_seek data_seek;		/* seek to next data */
	struct stats_seek dir_seek;		/* dir => ileaf seek */
};

struct stats_btree_level {
	struct stats_btree_block block;		/* block space stats */
	struct stats_seek child_seek;		/* seek to child object */
};

struct stats_btree {
	struct stats_seek depth_seek;		/* seek for depth-first */
	struct stats_btree_data data;		/* data blocks stats */
	int depth;
	struct stats_btree_level levels[];	/* block stats for each level */
};

struct stats_fs {
	struct stats_btree *own;
	struct stats_btree *dtree_sum;

	block_t logblock;			/* number of log blocks */
	block_t logblock_bytes;			/* number of log bytes */
	struct stats_seek logblock_seek;	/* seek for depth-first */
};

static double percentage(u64 numerator, u64 denominator)
{
	if (!denominator)
		return 0;
	return ((double)numerator / denominator) * 100;
}

static u64 average(u64 total, u64 nr)
{
	if (!nr)
		return 0;
	return total / nr;
}

static struct stats_btree *alloc_stats_btree(int depth)
{
	size_t size = sizeof(struct stats_btree) +
		depth * sizeof(struct stats_btree_level);
	struct stats_btree *own;

	own = malloc(size);
	if (!own)
		strerror_exit(1, ENOMEM, "malloc");

	memset(own, 0, size);
	own->depth	= depth;
	own->data.min	= UINT_MAX;

	return own;
}

static void free_stats_btree(struct stats_btree *stats)
{
	if (stats)
		free(stats);
}

static struct stats_fs init_stats_fs(struct btree *btree)
{
	int depth = btree->root.depth;

	if (!opt_stats)
		return (struct stats_fs){};
	return (struct stats_fs){ .own = alloc_stats_btree(depth), };
}

static void destroy_stats_fs(struct stats_fs *stats)
{
	free_stats_btree(stats->own);
	free_stats_btree(stats->dtree_sum);
}

static block_t stats_suppose_seek(block_t physical, unsigned count)
{
	static block_t last;
	block_t len = llabs(last - physical);

	trace("depth-first seek: %Lu => %Lu, seek %Lu", last, physical, len);
	last = physical + count;

	return len;
}

static void stats_seek_add(struct stats_seek *stats, block_t seek_len)
{
	stats->blocks += seek_len;
	stats->nr += !!seek_len;
	stats->io++;
}

static void stats_data_seek_add(struct stats_btree *stats, block_t block,
				unsigned count)
{
	block_t seek = llabs(block - (stats->data.last ? : block));
	stats_seek_add(&stats->data.data_seek, seek);
	stats->data.last = block + count;
}

static void stats_dir_seek_add(struct stats_btree *stats, block_t dir,
			       block_t ileaf)
{
	static block_t last_ileaf;
	block_t seek = llabs(ileaf - dir);

	trace("dir => ileaf seek: %Lu => %Lu, seek %Lu, last %Lu",
	      dir, ileaf, seek, last_ileaf);
	if (last_ileaf != ileaf) {
		stats_seek_add(&stats->data.dir_seek, seek);
		last_ileaf = ileaf;
	}
}

static void stats_child_seek_add(struct stats_btree *stats, int level,
				block_t cur, block_t child)
{
	block_t seek = llabs(child - (cur + 1));
	stats_seek_add(&stats->levels[level].child_seek, seek);
}

static void stats_block_add(struct stats_btree *stats, int level,
			    block_t block, unsigned bytes, int empty)
{
	block_t seek = stats_suppose_seek(block, 1);

	stats->levels[level].block.blocks++;
	stats->levels[level].block.empty += empty;
	stats->levels[level].block.bytes += bytes;

	stats_seek_add(&stats->depth_seek, seek);
}

static void stats_data_add(struct stats_btree *stats, block_t block,
			   unsigned count)
{
	block_t seek = stats_suppose_seek(block, count);

	stats->data.blocks += count;
	stats->data.nr++;
	stats->data.max = max(stats->data.max, count);
	stats->data.min = min(stats->data.min, count);

	stats_seek_add(&stats->depth_seek, seek);
}

static struct stats_btree_level
stats_levels_sum(struct stats_btree *stats, int depth)
{
	struct stats_btree_level sum = {};

	for (int i = 0; i < depth; i++) {
		sum.block.blocks	+= stats->levels[i].block.blocks;
		sum.block.empty		+= stats->levels[i].block.empty;
		sum.block.bytes		+= stats->levels[i].block.bytes;
		sum.child_seek.blocks	+= stats->levels[i].child_seek.blocks;
		sum.child_seek.nr	+= stats->levels[i].child_seek.nr;
		sum.child_seek.io	+= stats->levels[i].child_seek.io;
	}

	return sum;
}

static void stats_btree_merge(struct stats_btree **a, struct stats_btree *b)
{
	/* No need to merge */
	if (b == NULL)
		return;

	if (*a == NULL) {
		/* Just copy b to a */
		*a = alloc_stats_btree(b->depth);
	} else {
		/* Merge b to a */
		if ((*a)->depth < b->depth) {
			struct stats_btree *tmp = alloc_stats_btree(b->depth);

			/* Copy (*a) to tmp */
			tmp->depth_seek = (*a)->depth_seek;
			tmp->data = (*a)->data;
			for (int i = 0; i < (*a)->depth - 1; i++)
				tmp->levels[i] = (*a)->levels[i];
			/* Set leaf info to new depth */
			tmp->levels[tmp->depth-1] = (*a)->levels[(*a)->depth-1];

			free_stats_btree(*a);
			*a = tmp;
		}
	}

	/* Merge bnode => bnode, and leaf => leaf */
	for (int i = 0; i < b->depth; i++) {
		int level = (i <= b->depth - 2) ? i : (*a)->depth - 1;
		struct stats_btree_level *la = &(*a)->levels[level];
		struct stats_btree_level *lb = &b->levels[i];

		la->block.blocks	+= lb->block.blocks;
		la->block.empty		+= lb->block.empty;
		la->block.bytes		+= lb->block.bytes;
		la->child_seek.blocks	+= lb->child_seek.blocks;
		la->child_seek.nr	+= lb->child_seek.nr;
		la->child_seek.io	+= lb->child_seek.io;
	}

	(*a)->depth_seek.blocks	+= b->depth_seek.blocks;
	(*a)->depth_seek.nr	+= b->depth_seek.nr;
	(*a)->depth_seek.io	+= b->depth_seek.io;

	struct stats_btree_data *da = &(*a)->data;
	struct stats_btree_data *db = &b->data;
	da->blocks		+= db->blocks;
	da->nr			+= db->nr;
	da->max			= max(da->max, db->max);
	da->min			= min(da->min, db->min);
	da->data_seek.blocks	+= db->data_seek.blocks;
	da->data_seek.nr	+= db->data_seek.nr;
	da->data_seek.io	+= db->data_seek.io;
	da->dir_seek.blocks	+= db->dir_seek.blocks;
	da->dir_seek.nr		+= db->dir_seek.nr;
	da->dir_seek.io		+= db->dir_seek.io;
}

static void stats_print_seek(struct stats_seek *stats, const char *prefix)
{
	printf("%s seek:\n"
	       "    %14Lu blocks, %10Lu seeks,       %10Lu IO\n"
	       "    avg %13c      %10Lu blocks/seek, %10Lu blocks/IO\n",
	       prefix, stats->blocks, stats->nr, stats->io, ' ',
	       average(stats->blocks, stats->nr),
	       average(stats->blocks, stats->io));
}

static void stats_print_depth_seek(struct stats_seek *stats)
{
	stats_print_seek(stats, "depth-first");
}

static void stats_print_seeks(struct sb *sb, struct stats_btree *stats,
			      int data, int dir)
{
	for (int i = 0; i < stats->depth; i++) {
		char prefix[64];

		if (i <= stats->depth - 2)
			snprintf(prefix, sizeof(prefix), "level %d => %d",
				 i, i + 1);
		else
			strcpy(prefix, "leaf => child");

		stats_print_seek(&stats->levels[i].child_seek, prefix);
	}

	if (data)
		stats_print_seek(&stats->data.data_seek, "data => data");

	if (dir)
		stats_print_seek(&stats->data.dir_seek, "dir => ileaf");
}

static void stats_print_log(struct sb *sb, struct stats_fs *stats)
{
	block_t bytes;

	bytes = stats->logblock << sb->blockbits;
	printf("[log]\n");
	printf("logblock:\n"
	       "    %14Lu blocks, %14Lu bytes, %5.02f%% full\n",
	       stats->logblock, stats->logblock_bytes,
	       percentage(stats->logblock_bytes, bytes));

	stats_print_depth_seek(&stats->logblock_seek);
}

static void stats_print_level(struct sb *sb, struct stats_btree_level *level,
			      const char *prefix)
{
	block_t bytes;

	bytes = level->block.blocks << sb->blockbits;
	printf("%s:\n"
	       "    %14Lu blocks, %14Lu bytes, %5.02f%% full\n"
	       "    %14Lu blocks empty\n",
	       prefix, level->block.blocks, level->block.bytes,
	       percentage(level->block.bytes, bytes),
	       level->block.empty);
}

static void __printf(5, 6)
stats_print(struct sb *sb, struct stats_btree *stats, int data, int dir,
	    const char *fmt, ...)
{
	va_list ap;
	struct stats_btree_level sum;

	if (stats == NULL)
		return;

	printf("[");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("]\n");

	/* Calc sum of bnode */
	sum = stats_levels_sum(stats, stats->depth - 1);
	stats_print_level(sb, &sum, "bnode");

	stats_print_level(sb, &stats->levels[stats->depth - 1], "leaf");

	/* Calc sum of bnode + leaf */
	sum = stats_levels_sum(stats, stats->depth);
	stats_print_level(sb, &sum, "btree");

	if (data) {
		printf("data:\n"
		       "    %14Lu blocks"
		       " (extent: min %u, max %u, avg %Lu, nr %Lu)\n",
		       stats->data.blocks, stats->data.min, stats->data.max,
		       average(stats->data.blocks, stats->data.nr),
		       stats->data.nr);
	}

	stats_print_seeks(sb, stats, data, dir);
	stats_print_depth_seek(&stats->depth_seek);
}

struct dump_info {
	struct stats_fs *stats;
	void *private;
};

static void dump_bnode(struct btree *btree, struct buffer_head *buffer,
		       int level, void *data)
{
	struct dump_info *di = data;
	struct bnode *bnode = bufdata(buffer);
	block_t blocknr = buffer->index;
	struct index_entry *index = bnode->entries;
	int n;

	if (opt_stats) {
		for (n = 0; n < bcount(bnode); n++) {
			stats_child_seek_add(di->stats->own, level, blocknr,
					     be64_to_cpu(index[n].block));
		}

		unsigned bytes = sizeof(*bnode)
			+ sizeof(*index) * bcount(bnode);
		int empty = !bcount(bnode);

		stats_block_add(di->stats->own, level, blocknr, bytes, empty);
	}
}

static void dump_data_dir(struct btree *btree, struct buffer_head *leafbuf,
			  block_t block, tux_dirent *entry, void *data)
{
	if (opt_stats) {
		struct sb *sb = btree->sb;
		struct btree *itree = itree_btree(sb);
		struct dump_info *di = data;
		int err;

		struct cursor *cursor = alloc_cursor(itree, 0);
		if (!cursor)
			strerror_exit(1, ENOMEM, "alloc_cursor");

		down_read(&cursor->btree->lock);
		err = btree_probe(cursor, be64_to_cpu(entry->inum));
		if (err)
			strerror_exit(1, -err,
				      "btree_probe error for inum in dir");

		stats_dir_seek_add(di->stats->own, block,
				   bufindex(cursor_leafbuf(cursor)));

		release_cursor(cursor);

		up_read(&cursor->btree->lock);
		free_cursor(cursor);
	}
}

static void dump_dleaf_extent(struct btree *btree, struct buffer_head *leafbuf,
			      block_t index, block_t block, unsigned count,
			      void *data)
{
	struct dump_info *di = data;
	struct inode *inode = btree_inode(btree);

	if (S_ISDIR(inode->i_mode) && opt_stats)
		walk_extent_dir(btree, leafbuf, index, block, count,
				dump_data_dir, data);

	if (opt_stats) {
		int level = btree->root.depth - 1;

		stats_data_seek_add(di->stats->own, block, count);
		stats_child_seek_add(di->stats->own, level, bufindex(leafbuf),
				     block);
		stats_data_add(di->stats->own, block, count);
	}
}

static struct walk_dleaf_ops dump_dleaf_ops = {
	.extent = dump_dleaf_extent,
};

static void dump_dleaf(struct btree *btree, struct buffer_head *leafbuf,
			void *data)
{
	struct dump_info *di = data;
	struct dleaf *dleaf = bufdata(leafbuf);
	unsigned bytes = sizeof(*dleaf)
		+ sizeof(*dleaf->table) * be16_to_cpu(dleaf->count);
	int empty = dleaf_can_free(btree, dleaf);
	int level = btree->root.depth - 1;

	if (opt_stats) {
		stats_block_add(di->stats->own, level, bufindex(leafbuf),
				bytes, empty);
	}

	walk_dleaf(btree, leafbuf, &dump_dleaf_ops, di);
}

static struct walk_btree_ops dump_dtree_ops = {
	.bnode	= dump_bnode,
	.leaf	= dump_dleaf,
};

static const char *dtree_name[] = {
	[TUX_BITMAP_INO]	= "bitmap",
	[TUX_COUNTMAP_INO]	= "countmap",
	[TUX_VTABLE_INO]	= "vtable",
	[TUX_ATABLE_INO]	= "atable",
	[TUX_ROOTDIR_INO]	= "rootdir",
};

static void dump_ileaf_cb(struct buffer_head *leafbuf, int at,
			  struct inode *inode, void *data)
{
	if (!has_root(&tux_inode(inode)->btree))
		return;

	struct dump_info *di = data;
	struct btree *dtree = &tux_inode(inode)->btree;
	inum_t inum = tux_inode(inode)->inum;

	/* for dump dtree */
	struct stats_fs stats_dtree = init_stats_fs(dtree);
	struct dump_info di_dtree = {
		.stats = &stats_dtree,
	};

	walk_btree(dtree, &dump_dtree_ops, &di_dtree);

	if (opt_stats > 1) {
		int special_inode;
		if (inum < ARRAY_SIZE(dtree_name) && dtree_name[inum])
			special_inode = 1;
		else
			special_inode = 0;

		if (special_inode) {
			stats_print(dtree->sb, stats_dtree.own,
				    1, S_ISDIR(inode->i_mode),
				    "dtree, %s", dtree_name[inum]);
		} else {
			stats_print(dtree->sb, stats_dtree.own,
				    1, S_ISDIR(inode->i_mode),
				    "dtree, inum %Lu", inum);
		}
	} else if (opt_stats) {
		static int print_once;
		if (!print_once) {
			print_once++;
			printf("Per-inode stats was suppressed."
			       " To see per-inode stats, use -s -s.\n");
		}
	}
	if (opt_stats) {
		/* Merge dtree stats to dtree_sum */
		stats_btree_merge(&di->stats->dtree_sum, stats_dtree.own);
	}

	destroy_stats_fs(&stats_dtree);
}

typedef void (*dump_ileaf_attr_t)(struct dump_info *, struct btree *,
				  struct buffer_head *, inum_t, void *, u16);

static void dump_ileaf_attr(struct dump_info *di, struct btree *btree,
			    struct buffer_head *leafbuf, inum_t inum,
			    void *attrs, u16 size)
{
	struct sb *sb = btree->sb;
	struct inode *inode = rapid_open_inode(sb, NULL, 0);
#if 0
	/* Check there is orphaned inode */
	struct inode *cache_inode = tux3_ilookup(sb, inum);
	int orphan = 0;
	if (cache_inode) {
		orphan = tux3_inode_is_orphan(tux_inode(cache_inode));
		iput(cache_inode);
	}
#endif
	iattr_ops.decode(btree, inode, attrs, size);

	if (opt_stats && has_root(&tux_inode(inode)->btree)) {
		int level = btree->root.depth - 1;
		stats_child_seek_add(di->stats->own, level, bufindex(leafbuf),
				     tux_inode(inode)->btree.root.block);
	}

	free_xcache(inode);
	free_map(inode->map);
}

static void __dump_ileaf(struct dump_info *di, struct btree *btree,
			 struct buffer_head *leafbuf,
			 dump_ileaf_attr_t dump_ileaf_attr)
{
	struct ileaf *ileaf = bufdata(leafbuf);
	__be16 *dict = ileaf_dict(btree, ileaf);
	int at;

	/* draw inode attributes */
	u16 offset = 0, limit, size;
	for (at = 0; at < icount(ileaf); at++) {
		limit = __atdict(dict, at + 1);
		if (offset >= limit)
			continue;
		size = limit - offset;

		inum_t inum = ibase(ileaf) + at;
		void *attrs = ileaf->table + offset;

		offset = limit;

		dump_ileaf_attr(di, btree, leafbuf, inum, attrs, size);
	}

	if (opt_stats) {
		unsigned bytes = sizeof(*ileaf) + ileaf_need(btree, ileaf);
		int empty = btree->ops->leaf_can_free(btree, ileaf);
		int level = btree->root.depth - 1;

		stats_block_add(di->stats->own, level, bufindex(leafbuf),
				bytes, empty);
	}
}

static void dump_ileaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	__dump_ileaf(data, btree, leafbuf, dump_ileaf_attr);
	walk_ileaf(btree, leafbuf, dump_ileaf_cb, data);
}

static struct walk_btree_ops dump_itree_ops = {
	.bnode	= dump_bnode,
	.leaf	= dump_ileaf,
};

static void dump_oleaf_attr(struct dump_info *di, struct btree *btree,
			    struct buffer_head *leafbuf, inum_t inum,
			    void *attrs, u16 size)
{
}

static void dump_oleaf(struct btree *btree, struct buffer_head *leafbuf,
		       void *data)
{
	__dump_ileaf(data, btree, leafbuf, dump_oleaf_attr);
}

static struct walk_btree_ops dump_otree_ops = {
	.bnode	= dump_bnode,
	.leaf	= dump_oleaf,
};

static void dump_log_pre(struct sb *sb, struct buffer_head *buffer,
			 unsigned logcount, int obsolete, void *data)
{
	struct dump_info *di = data;
	struct logblock *log = bufdata(buffer);

	if (opt_stats) {
		block_t seek = stats_suppose_seek(bufindex(buffer), 1);
		unsigned bytes = sizeof(*log) + be16_to_cpu(log->bytes);

		di->stats->logblock++;
		di->stats->logblock_bytes += bytes;
		stats_seek_add(&di->stats->logblock_seek, seek);
	}
}

static struct walk_logchain_ops dump_logchain_ops = {
	.pre	= dump_log_pre,
};

static int dump_main(struct sb *sb, int verbose)
{
	int err;

	if (verbose)
		opt_stats++;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		return err;
	}

	struct stats_fs stats_itree = init_stats_fs(itree_btree(sb));
	struct stats_fs stats_otree = init_stats_fs(otree_btree(sb));
	struct dump_info dump_info = {
		.stats = &stats_itree,
	};

	walk_logchain(sb, &dump_logchain_ops, &dump_info);
	walk_btree(itree_btree(sb), &dump_itree_ops, &dump_info);

	dump_info.stats = &stats_otree;
	walk_btree(otree_btree(sb), &dump_otree_ops, &dump_info);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	if (opt_stats) {
		stats_print(sb, stats_itree.dtree_sum, 1, 1, "dtree");
		stats_print(sb, stats_itree.own, 0, 0, "itree");
		stats_print(sb, stats_otree.own, 0, 0, "otree");

		stats_print_log(sb, &stats_itree);

		stats_btree_merge(&stats_itree.own, stats_itree.dtree_sum);
		stats_btree_merge(&stats_itree.own, stats_otree.own);
		stats_print(sb, stats_itree.own, 1, 1, "total");
	}

	destroy_stats_fs(&stats_itree);
	destroy_stats_fs(&stats_otree);

	return 0;
}
