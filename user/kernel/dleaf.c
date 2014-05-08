/*
 * File index btree leaf operations.
 *
 * Copyright (c) 2012-2014 Daniel Phillips
 * Copyright (c) 2012-2014 OGAWA Hirofumi
 */

/*
 * The dleaf extent table is sorted by logical address. Note that
 * binsearch may be on the whole 64 bit logical:verhi pair even if
 * verhi: has random data, because the logical part of the combined
 * quantity is more significant. Until extent versioning arrives,
 * verhi:verlo will always be zero.
 *
 * Explicit extent counts are not present. Extent count is given by
 * the difference between two successive logical addresses or the
 * difference between the logical addresses of the first entry of one
 * block and the final entry of the previous block. (In all cases,
 * provided the logical addresses are not equal, see below.)
 *
 * A hole between allocated data regions is indicated explicitly by an
 * extent with physical address zero, which is not valid for any
 * actual allocated extent because the filesystem header (including
 * superblock) occupies that address.
 *
 * Two adjacent entries may have the same logical address, which means
 * they are different versions of the same extent. All the version
 * numbers in a sequence of equal logical extents must be different,
 * or all zero. To find the length of a group of equal logical
 * extents, scan forward to the first nonequal logical extent, which
 * normally will be nearby.
 */

#include "tux3.h"
#include "dleaf.h"

/*
 * The uptag is for filesystem integrity checking and corruption
 * repair. It provides the low order bits of the delta at which the
 * leaf was committed, the inode number to which it belongs, and the
 * logical position within that inode.
 */
struct uptag {
	__be32 inum;
	__be32 offset;
	__be16 future;
	__be16 delta;
};

/* FIXME: ignoring version at all */

#define VER_BITS		16
#define VER_MASK		((1 << VER_BITS))
#define ADDR_BITS		48
#define ADDR_MASK		((1ULL << ADDR_BITS) - 1)

struct dleaf {
	__be16 magic;			/* dleaf magic */
	__be16 count;			/* count of diskextent2 */
//	struct uptag tag;
	__be32 __unused;
	struct diskextent2 {
		__be64 verhi_logical;	/* verhi:16, logical:48 */
		__be64 verlo_physical;	/* verlo:16, physical:48 */
	} table[];
};

struct extent {
	u32 version;		/* version */
	block_t logical;	/* logical address */
	block_t physical;	/* physical address */
};

static inline block_t get_logical(struct diskextent2 *dex)
{
	return be64_to_cpu(dex->verhi_logical) & ADDR_MASK;
}

static inline void get_extent(struct diskextent2 *dex, struct extent *ex)
{
	u64 val;

	val = be64_to_cpu(dex->verhi_logical);
	ex->version = val >> ADDR_BITS;
	ex->logical = val & ADDR_MASK;

	val = be64_to_cpu(dex->verlo_physical);
	ex->version = (ex->version << VER_BITS) | (val >> ADDR_BITS);
	ex->physical = val & ADDR_MASK;
}

static inline void put_extent(struct diskextent2 *dex, u32 version,
			      block_t logical, block_t physical)
{
	u64 verhi = version >> VER_BITS, verlo = version & VER_MASK;
	dex->verhi_logical  = cpu_to_be64(verhi << ADDR_BITS | logical);
	dex->verlo_physical = cpu_to_be64(verlo << ADDR_BITS | physical);
}

static void dleaf_btree_init(struct btree *btree)
{
	struct sb *sb = btree->sb;
	unsigned datasize = sb->blocksize - sizeof(struct dleaf);
	btree->entries_per_leaf = datasize / sizeof(struct diskextent2);
}

static int dleaf_init(struct btree *btree, void *leaf)
{
	struct dleaf *dleaf = leaf;
	*dleaf = (struct dleaf){
		.magic = cpu_to_be16(TUX3_MAGIC_DLEAF),
		.count = 0,
	};
	/* FIXME: should be refactoring and remove this from split path */
	if (has_direct_extent(btree)) {
		/* Convert direct extent to leaf */
		struct sb *sb = btree->sb;
		struct diskextent2 *dex = dleaf->table;

		dleaf->count = cpu_to_be16(2);
		put_extent(dex, sb->version, 0, btree->root.block);
		put_extent(dex + 1, sb->version, btree->root.count, 0);

		btree->root = no_root;
	}
	return 0;
}

static int dleaf_sniff(struct btree *btree, void *leaf)
{
	struct dleaf *dleaf = leaf;
	if (dleaf->magic != cpu_to_be16(TUX3_MAGIC_DLEAF))
		return -1;
	if (dleaf->count) {
		/* Last should be sentinel */
		struct extent ex;
		get_extent(dleaf->table + be16_to_cpu(dleaf->count) - 1, &ex);
		if (ex.physical != 0)
			return -1;
	}
	return 0;
}

static int dleaf_can_free(struct btree *btree, void *leaf)
{
	struct dleaf *dleaf = leaf;
	unsigned count = be16_to_cpu(dleaf->count);

	assert(!dleaf_sniff(btree, dleaf));
	if (count > 1)
		return 0;
	return 1;
}

/* Lookup logical address in diskextent2 <= index */
static struct diskextent2 *
__dleaf_lookup_index(struct btree *btree, struct dleaf *dleaf,
		      struct diskextent2 *start, struct diskextent2 *limit,
		      tuxkey_t index)
{
#if 1
	/* Paranoia check: last should be sentinel (hole) */
	if (dleaf->count) {
		struct extent ex;
		get_extent(dleaf->table + be16_to_cpu(dleaf->count) - 1, &ex);
		assert(ex.physical == 0);
	}
#endif
	/* FIXME: binsearch here */
	while (start < limit) {
		if (index == get_logical(start))
			return start;
		else if (index < get_logical(start)) {
			/* should have diskextent2 of bottom logical on leaf */
			assert(dleaf->table < start);
			return start - 1;
		}
		start++;
	}

	return start;
}

static struct diskextent2 *
dleaf_lookup_index(struct btree *btree, struct dleaf *dleaf, tuxkey_t index)
{
	struct diskextent2 *start = dleaf->table;
	struct diskextent2 *limit = start + be16_to_cpu(dleaf->count);

	return __dleaf_lookup_index(btree, dleaf, start, limit, index);
}

/*
 * Split diskextent2, and return split key.
 */
static tuxkey_t dleaf_split(struct btree *btree, tuxkey_t hint,
			     void *vfrom, void *vinto)
{
	struct dleaf *from = vfrom, *into = vinto;
	struct diskextent2 *dex;
	struct extent ex;
	unsigned split_at, count = be16_to_cpu(from->count);

	/* need 2 extents except sentinel, at least */
	assert(count >= 3);

	/*
	 * Honor hint key, then copy and set new sentinel.
	 */

	dex = dleaf_lookup_index(btree, from, hint);
	if (dex == from->table + count) {
#if 1
		get_extent(dex - 1, &ex);
		assert(ex.physical == 0);
		return ex.logical;	/* use sentinel of previous leaf */
#else
		/* FIXME: not necessary to store between sentinel and hint */
		return hint;
#endif
	}

	split_at = dex - from->table;

	from->count = cpu_to_be16(split_at + 1);	/* +1 for sentinel */
	into->count = cpu_to_be16(count - split_at);

	dex = from->table + split_at;
	/* Copy diskextent2 */
	memcpy(into->table, dex, sizeof(*dex) * (count - split_at));
	/* Put sentinel */
	get_extent(dex, &ex);
	put_extent(dex, ex.version, ex.logical, 0);

	return ex.logical;
}

/*
 * Try to merge from vfrom into vinto
 * return value:
 * 0 - couldn't merge
 * 1 - merged
 */
static int dleaf_merge(struct btree *btree, void *vinto, void *vfrom)
{
	struct dleaf *into = vinto, *from = vfrom;
	struct extent into_ex, from_ex;
	unsigned into_count, from_count;
	int can_merge, from_size;

	/* If "from" is empty or sentinel only, does nothing */
	from_count = be16_to_cpu(from->count);
	if (from_count <= 1)
		return 1;

	from_size = sizeof(from->table[0]) * from_count;
	/* If "into" is empty, just copy. FIXME: why there is no sentinel? */
	into_count = be16_to_cpu(into->count);
	if (!into_count) {
		into->count = from->count;
		from->count = 0;
		memcpy(into->table, from->table, from_size);
		return 1;
	}

	/* Try merge end of "from" and start of "into" */
	get_extent(into->table + into_count - 1, &into_ex);
	get_extent(from->table, &from_ex);
	assert(into_ex.logical <= from_ex.logical);
	assert(into_ex.physical == 0);
	can_merge = 0;
	/* If start of "from" is hole, it can be merged */
	if (!from_ex.physical)
		can_merge = 1;
	/* If logical is same, it can be merged */
	if (into_ex.logical == from_ex.logical)
		can_merge = 1;

	if (into_count + from_count - can_merge > btree->entries_per_leaf)
		return 0;

	if (!from_ex.physical) {
		/* If start of "from" is hole, use logical of sentinel */
		from_size -= sizeof(from->table[0]) * can_merge;
		memcpy(into->table + into_count, from->table + 1, from_size);
	} else if (into_ex.logical == from_ex.logical) {
		/* If logical is same, use logical of "from" */
		memcpy(into->table + into_count - 1, from->table, from_size);
	} else {
		/* Other cases are just copy */
		memcpy(into->table + into_count, from->table, from_size);
	}
	into->count = cpu_to_be16(into_count + from_count - can_merge);
	from->count = 0;

	return 1;
}

/*
 * Chop diskextent2
 * return value:
 * < 0 - error
 *   1 - modified
 *   0 - not modified
 */
static int dleaf_chop(struct btree *btree, tuxkey_t start, u64 len, void *leaf)
{
	struct sb *sb = btree->sb;
	struct dleaf *dleaf = leaf;
	struct diskextent2 *dex, *dex_limit;
	struct extent ex;
	block_t block;
	int need_sentinel;

	/* FIXME: range chop is unsupported for now */
	assert(len == TUXKEY_LIMIT);

	if (!dleaf->count)
		return 0;

	dex_limit = dleaf->table + be16_to_cpu(dleaf->count);
	/* Lookup the extent is including index */
	dex = dleaf_lookup_index(btree, dleaf, start);
	if (dex >= dex_limit - 1)
		return 0;

	need_sentinel = 1;
	get_extent(dex, &ex);
	if (start == ex.logical) {
		if (dex > dleaf->table) {
			/* If previous is hole, use it as sentinel */
			struct extent prev;
			get_extent(dex - 1, &prev);
			if (prev.physical == 0) {
				dex--;
				need_sentinel = 0;
			}
		}
		if (need_sentinel) {
			/* Put new sentinel here. */
			put_extent(dex, sb->version, start, 0);
		}
		need_sentinel = 0;
	} else if (ex.physical == 0) {
		/* If chop point is hole, use it as sentinel */
		start = ex.logical;
		need_sentinel = 0;
	}
	/* Shrink space */
	dleaf->count = cpu_to_be16((dex - dleaf->table) + 1 + need_sentinel);

	block = ex.physical + (start - ex.logical);
	dex++;

	while (dex < dex_limit) {
		unsigned count;

		/* Get next diskextent2 */
		get_extent(dex, &ex);
		count = ex.logical - start;
		if (block && count) {
			defer_bfree(sb, &sb->defree, block, count);
			log_bfree(sb, block, count);
		}

		if (need_sentinel) {
			/* Put new sentinel */
			put_extent(dex, sb->version, start, 0);
			need_sentinel = 0;
		}
		start = ex.logical;
		block = ex.physical;
		dex++;
	}

	return 1;
}

/* Read extents */
static unsigned __dleaf_read(struct btree *btree, tuxkey_t key_bottom,
			      tuxkey_t key_limit,
			      struct dleaf *dleaf, struct btree_key_range *key,
			      int stop_at_hole)
{
	struct dleaf_req *rq = container_of(key, struct dleaf_req, key);
	tuxkey_t key_start = key->start;
	unsigned key_len = key->len;
	struct diskextent2 *dex, *dex_limit;
	struct extent next;
	block_t physical;

	if (rq->seg_cnt >= rq->seg_max)
		return 0;

	dex_limit = dleaf->table + be16_to_cpu(dleaf->count);

	/* Lookup the extent is including index */
	dex = dleaf_lookup_index(btree, dleaf, key_start);
	if (dex >= dex_limit - 1) {
		/* If sentinel, fill by bottom key */
		goto fill_seg;
	}

	/* Get start position of logical and physical */
	get_extent(dex, &next);
	physical = next.physical;
	if (physical)
		physical += key_start - next.logical;	/* add offset */

	do {
		struct block_segment *seg = rq->seg + rq->seg_cnt;

		dex++;
		get_extent(dex, &next);

		/* Check of logical addr range of current and next. */
		seg->count = min_t(u64, key_len, next.logical - key_start);
		if (physical) {
			seg->block = physical;
			seg->state = 0;
		} else {
			seg->block = 0;
			seg->state = BLOCK_SEG_HOLE;
		}

		physical = next.physical;
		key_start += seg->count;
		key_len -= seg->count;
		rq->seg_cnt++;

		/* Stop if current is hole and next is segment */
		if (stop_at_hole) {
			if (!seg->block && physical)
				break;
		}
	} while (key_len && rq->seg_cnt < rq->seg_max && dex + 1 < dex_limit);

fill_seg:
	/* Between sentinel and key_limit is hole */
	if (key_start < key_limit && key_len && rq->seg_cnt < rq->seg_max) {
		struct block_segment *seg = rq->seg + rq->seg_cnt;

		seg->count = min_t(tuxkey_t, key_len, key_limit - key_start);
		seg->block = 0;
		seg->state = BLOCK_SEG_HOLE;

		key_start += seg->count;
		key_len -= seg->count;
		rq->seg_cnt++;
	}

	return key->len - key_len;
}

/* Read extents */
static int dleaf_read(struct btree *btree, tuxkey_t key_bottom,
		       tuxkey_t key_limit,
		       void *leaf, struct btree_key_range *key)
{
	struct dleaf *dleaf = leaf;
	unsigned len;

	len = __dleaf_read(btree, key_bottom, key_limit, dleaf, key, 0);
	key->start += len;
	key->len -= len;

	return 0;
}

static int dleaf_pre_write(struct btree *btree, tuxkey_t key_bottom,
			    tuxkey_t key_limit, void *leaf,
			    struct btree_key_range *key)
{
	struct dleaf_req *rq = container_of(key, struct dleaf_req, key);
	struct dleaf *dleaf = leaf;

	/*
	 * If overwrite mode, read exists segments. Then, if there are
	 * hole, allocate segment.
	 */
	if (rq->overwrite) {
		unsigned len;
		int last, hole_len;

		len = __dleaf_read(btree, key_bottom, key_limit, dleaf, key, 1);
		last = rq->seg_cnt;

		/* Remove hole from seg[] */
		hole_len = 0;
		while (last > rq->seg_idx && !rq->seg[last - 1].block) {
			len -= rq->seg[last - 1].count;
			hole_len += rq->seg[last - 1].count;
			last--;
		}
		key->start += len;
		key->len = hole_len;
		rq->seg_idx = last;
		rq->seg_cnt = last;

		/* If there is no hole, return exists segments */
		if (!hole_len)
			return BTREE_DO_RETRY;
	}

	return BTREE_DO_DIRTY;
}


/* Resize dleaf from head */
static void dleaf_resize(struct dleaf *dleaf, struct diskextent2 *head,
			  int diff)
{
	void *limit = dleaf->table + be16_to_cpu(dleaf->count);

	if (diff == 0)
		return;

	memmove(head + diff, head, limit - (void *)head);
	be16_add_cpu(&dleaf->count, diff);
}

/* Initialize sentinel by bottom key */
static inline void dleaf_init_sentinel(struct sb *sb, struct dleaf *dleaf,
					tuxkey_t key_bottom)
{
	if (!dleaf->count) {
		dleaf->count = cpu_to_be16(1);
		put_extent(dleaf->table, sb->version, key_bottom, 0);
	}
}

/* Return split key of center for split hint */
static tuxkey_t dleaf_split_at_center(struct dleaf *dleaf)
{
	struct extent ex;
	get_extent(dleaf->table + be16_to_cpu(dleaf->count) / 2, &ex);
	return ex.logical;
}

/* dex information to modify */
struct dex_info {
	/* start extent */
	struct diskextent2 *start_dex;
	/* physical range of partial start */
	block_t start_block;
	unsigned start_count;

	/* end extent */
	struct diskextent2 *end_dex;
	/* remaining physical range of partial end */
	block_t end_block;

	int dleaf_count;	/* count of dex except overwritten */
	int overwrite_cnt;	/* count of dex overwritten */
	int need_sentinel;	/* segments needs new sentinel? */
};

static void find_start_dex(struct btree *btree, struct dleaf *dleaf,
			   block_t key_start, struct dex_info *info)
{
	struct diskextent2 *dex_limit;

	dex_limit = dleaf->table + be16_to_cpu(dleaf->count);

	info->start_block = 0;
	info->start_count = 0;

	/* Lookup the dex for start of seg[]. */
	info->start_dex = dleaf_lookup_index(btree, dleaf, key_start);
	if (info->start_dex < dex_limit - 1) {
		struct extent ex;

		get_extent(info->start_dex, &ex);
		/* Start is at middle of dex: can't overwrite this dex */
		if (key_start > ex.logical) {
			block_t prev = ex.logical, physical = ex.physical;

			info->start_dex++;
			get_extent(info->start_dex, &ex);

			if (physical)
				info->start_block = physical + key_start - prev;
			info->start_count = ex.logical - key_start;
		}
	}
}

static void find_end_dex(struct btree *btree, struct dleaf *dleaf,
			 block_t key_end, struct dex_info *info)
{
	struct diskextent2 *limit, *dex_limit;
	u16 dleaf_count = be16_to_cpu(dleaf->count);

	dex_limit = dleaf->table + dleaf_count;

	info->need_sentinel = 0;
	info->end_block = 0;
	info->dleaf_count = dleaf_count;

	if (!info->end_dex) {
		/* Initial lookup */
		limit = dex_limit;
	} else {
		/* Retry, we can limit lookup region */
		limit = min(info->end_dex + 1, dex_limit);
	}

	/* Lookup the dex for end of seg[]. */
	info->end_dex = __dleaf_lookup_index(btree, dleaf, info->start_dex,
					      limit, key_end);
	if (info->end_dex < dex_limit - 1) {
		struct extent ex;

		get_extent(info->end_dex, &ex);
		if (key_end > ex.logical) {
			block_t offset = key_end - ex.logical;

			/* End is at middle of dex: can overwrite this dex */
			info->end_dex++;

			/* Need new end of segment */
			info->need_sentinel = 1;
			/* Save new physical for end of seg[] */
			if (ex.physical)
				info->end_block = ex.physical + offset;
		}
	}
	assert(info->start_dex <= info->end_dex);

	/*
	 * Calculate dleaf space informations
	 */
	/* Number of dex can be overwritten */
	info->overwrite_cnt = info->end_dex - info->start_dex;
	/* Need new dex sentinel? */
	info->need_sentinel |= info->end_dex == dex_limit;

	/* Calculate new dleaf->count except dex is overwritten by segments. */
	info->dleaf_count -= info->overwrite_cnt;
	info->dleaf_count += info->need_sentinel;
}

/*
 * Write extents.
 */
static int dleaf_write(struct btree *btree, tuxkey_t key_bottom,
			tuxkey_t key_limit,
			void *leaf, struct btree_key_range *key,
			tuxkey_t *split_hint)
{
	struct dleaf_req *rq = container_of(key, struct dleaf_req, key);
	struct sb *sb = btree->sb;
	struct dleaf *dleaf = leaf;
	struct diskextent2 *dex;
	struct extent ex;
	struct dex_info info;
	unsigned free_len, seg_len, alloc_len;
	int err, diff, seg_cnt, space;

	/*
	 * Strategy: check free space in dleaf, then allocate
	 * segments, and write segments to dleaf. If there is no
	 * space in dleaf, shrink segments to fit space of dleaf,
	 * and split.
	 *
	 * FIXME: should try to merge at start and new last extents.
	 */

	dleaf_init_sentinel(sb, dleaf, key_bottom);

	/* Get the info of dex for start of seg[]. */
	find_start_dex(btree, dleaf, key->start, &info);

	seg_len = min_t(tuxkey_t, key_limit - key->start, key->len);
	/* Get the info of dex for end of seg[]. */
	info.end_dex = NULL;
	find_end_dex(btree, dleaf, key->start + seg_len, &info);

	/*
	 * Allocate blocks to seg after dleaf redirect. With this, our
	 * allocation order is, bnode => dleaf => data, and we can use
	 * physical address of dleaf as allocation hint for data
	 * blocks.
	 */
	space = btree->entries_per_leaf - info.dleaf_count;
#if 0
	/* If there is no space to store 1 dex (start and end), split */
	if (space <= 2)
		goto need_split;
#else
	/* If there is no space, split */
	if (space <= 0)
		goto need_split;
#endif

	err = rq->seg_find(btree, rq, space, seg_len, &alloc_len);
	if (err < 0) {
		assert(err != -ENOSPC);	/* block reservation bug */
		tux3_err(sb, "extent allocation failed: %d", err);
		return err;
	}
	seg_cnt = rq->seg_cnt - rq->seg_idx;
	assert(seg_cnt > 0);

	/* Ugh, there was not space enough to store, adjust number of seg[]. */
	while (seg_len != alloc_len) {
		seg_len = alloc_len;
		/* Re-calculate end of seg[] can be allocated */
		find_end_dex(btree, dleaf, key->start + alloc_len, &info);

		/* Shrink segments to fit to space of dleaf */
		while (info.dleaf_count + seg_cnt > btree->entries_per_leaf) {
			seg_cnt--;
			alloc_len -= rq->seg[rq->seg_idx + seg_cnt].count;
			if (!seg_cnt) {
				/* Didn't fit at all, cancel allocation */
				rq->seg_alloc(btree, rq, 0);
				goto need_split;
			}
		}
	}

	/* Commit allocation of writable segments */
	err = rq->seg_alloc(btree, rq, seg_cnt);
	assert(key->start + seg_len <= key_limit);
#if 0
	tux3_dbg("start %lu, end %lu",
		 info.start_dex - dleaf->table, info.end_dex - dleaf->table);
	tux3_dbg("dleaf_count %u (%u) (seg_cnt %u, overwrite %lu, sentinel %u)",
		 info.dleaf_count, info.dleaf_count + seg_cnt,
		 seg_cnt, info.end_dex - info.start_dex, info.need_sentinel);
#endif

	/*
	 * Free segments which is overwritten.
	 */
	free_len = seg_len;
	if (info.start_count) {
		unsigned count = min_t(block_t, free_len, info.start_count);
		if (info.start_block)
			rq->seg_free(btree, info.start_block, count);
		free_len -= count;
	}
	if (info.start_dex < info.end_dex) {
		struct diskextent2 *limit = info.end_dex;

		if (limit != dleaf->table + be16_to_cpu(dleaf->count))
			limit++;

		get_extent(info.start_dex, &ex);
		for (dex = info.start_dex + 1; free_len && dex < limit; dex++) {
			block_t prev = ex.logical, physical = ex.physical;
			unsigned count;

			get_extent(dex, &ex);
			count = min_t(block_t, free_len, ex.logical - prev);
			if (physical)
				rq->seg_free(btree, physical, count);
			free_len -= count;
		}
	}

	/* Calculate difference of dleaf->count on old and new. */
	diff = seg_cnt - info.overwrite_cnt + info.need_sentinel;
	/*
	 * Expand/shrink space for segs
	 */
	dleaf_resize(dleaf, info.end_dex,  diff);
	assert(info.dleaf_count + seg_cnt == be16_to_cpu(dleaf->count));
	assert(info.dleaf_count + seg_cnt <= btree->entries_per_leaf);

	/*
	 * Fill extents
	 */
	while (seg_len) {
		struct block_segment *seg = rq->seg + rq->seg_idx;

		put_extent(info.start_dex, sb->version, key->start, seg->block);

		key->start += seg->count;
		key->len -= seg->count;

		seg_len -= seg->count;
		rq->seg_idx++;
		info.start_dex++;
	}
	if (info.need_sentinel) {
		/* Fill sentinel */
		put_extent(info.start_dex, sb->version, key->start,
			   info.end_block);
	}

	if (rq->seg_cnt == rq->seg_max) {
		/* Stop if there is no space in seg[] */
		key->len = 0;
	} else if (key->start < key_limit && key->len) {
		/* If there are remaining range, split */
		goto need_split;
	}

	return BTREE_DO_RETRY;

need_split:
	/* FIXME: do we should split at sentinel when filling hole? */
	if (key_limit == TUXKEY_LIMIT) {
		struct diskextent2 *sentinel =
			dleaf->table + be16_to_cpu(dleaf->count) - 1;

		/* If append write, split at sentinel */
		*split_hint = get_logical(sentinel);
		if (key->start >= *split_hint) {
			tux3_dbg("key %Lu bottom %Lu, limit %Lu, hint %Lu",
				 key->start, key_bottom, key_limit,
				 *split_hint);
			return BTREE_DO_SPLIT;
		}
	}

	/* FIXME: use better split position */
	*split_hint = dleaf_split_at_center(dleaf);
	return BTREE_DO_SPLIT;
}

struct btree_ops dtree_ops = {
	.btree_init	= dleaf_btree_init,
	.leaf_init	= dleaf_init,
	.leaf_split	= dleaf_split,
	.leaf_merge	= dleaf_merge,
	.leaf_chop	= dleaf_chop,
	.leaf_pre_write	= dleaf_pre_write,
	.leaf_write	= dleaf_write,
	.leaf_read	= dleaf_read,

	.leaf_sniff	= dleaf_sniff,
	.leaf_can_free	= dleaf_can_free,
};
