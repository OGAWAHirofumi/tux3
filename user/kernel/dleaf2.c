/*
 * File index btree leaf operations
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
#include "dleaf2.h"

/*
 * The uptag is for filesystem integrity checking and corruption
 * repair. It provides the low order bits of the delta at which the
 * leaf was committed, the inode number to which it belongs, and the
 * logical position within that inode.
 */
struct uptag {
	be_u32 inum;
	be_u32 offset;
	be_u16 future;
	be_u16 delta;
};

/* FIXME: ignoring version at all */

#define VER_BITS		16
#define VER_MASK		((1 << VER_BITS))
#define ADDR_BITS		48
#define ADDR_MASK		((1ULL << ADDR_BITS) - 1)

struct dleaf2 {
	be_u16 magic;			/* dleaf2 magic */
	be_u16 count;			/* count of diskextent2 */
//	struct uptag tag;
	be_u32 __unused;
	struct diskextent2 {
		be_u64 verhi_logical;	/* verhi:16, logical:48 */
		be_u64 verlo_physical;	/* verlo:16, physical:48 */
	} table[];
};

struct extent {
	u32 version;		/* version */
	block_t logical;	/* logical address */
	block_t physical;	/* physical address */
};

static inline block_t get_logical(struct diskextent2 *dex)
{
	return from_be_u64(dex->verhi_logical) & ADDR_MASK;
}

static inline void get_extent(struct diskextent2 *dex, struct extent *ex)
{
	u64 val;

	val = from_be_u64(dex->verhi_logical);
	ex->version = val >> ADDR_BITS;
	ex->logical = val & ADDR_MASK;

	val = from_be_u64(dex->verlo_physical);
	ex->version = (ex->version << VER_BITS) | (val >> ADDR_BITS);
	ex->physical = val & ADDR_MASK;
}

static inline void put_extent(struct diskextent2 *dex, u32 version,
			      block_t logical, block_t physical)
{
	u64 verhi = version >> VER_BITS, verlo = version & VER_MASK;
	dex->verhi_logical  = to_be_u64(verhi << ADDR_BITS | logical);
	dex->verlo_physical = to_be_u64(verlo << ADDR_BITS | physical);
}

static void dleaf2_btree_init(struct btree *btree)
{
	struct sb *sb = btree->sb;
	unsigned datasize = sb->blocksize - sizeof(struct dleaf2);
	btree->entries_per_leaf = datasize / sizeof(struct diskextent2);
}

static int dleaf2_init(struct btree *btree, void *leaf)
{
	struct dleaf2 *dleaf = leaf;
	*dleaf = (struct dleaf2){
		.magic = to_be_u16(TUX3_MAGIC_DLEAF2),
		.count = 0,
	};
	return 0;
}

static int dleaf2_sniff(struct btree *btree, void *leaf)
{
	struct dleaf2 *dleaf = leaf;
	if (dleaf->magic != to_be_u16(TUX3_MAGIC_DLEAF2))
		return 1;
	if (!dleaf->count)
		return 1;
	/* Last should be sentinel */
	struct extent ex;
	get_extent(dleaf->table + from_be_u16(dleaf->count) - 1, &ex);
	if (ex.physical == 0)
		return 1;
	return 0;
}

static int dleaf2_can_free(struct btree *btree, void *leaf)
{
	struct dleaf2 *dleaf = leaf;
	unsigned count = from_be_u16(dleaf->count);

	assert(dleaf2_sniff(btree, dleaf));
	if (count > 1)
		return 0;
	return 1;
}

static void dleaf2_dump(struct btree *btree, void *leaf)
{
}

/* Lookup logical address in diskextent2 <= index */
static struct diskextent2 *
dleaf2_lookup_index(struct btree *btree, struct dleaf2 *dleaf, tuxkey_t index)
{
	struct diskextent2 *dex = dleaf->table;
	struct diskextent2 *limit = dex + from_be_u16(dleaf->count);

	/* FIXME: binsearch here */
	while (dex < limit) {
		if (index == get_logical(dex))
			return dex;
		else if (index < get_logical(dex)) {
			/* should have diskextent2 of bottom logical on leaf */
			assert(dleaf->table < dex);
			return dex - 1;
		}
		dex++;
	}

	/* Not found - last should be sentinel (hole) */
	if (dleaf->count) {
		struct extent ex;
		get_extent(dex - 1, &ex);
		assert(ex.physical == 0);
	}

	return dex;
}

/*
 * Split diskextent2, and return split key.
 */
static tuxkey_t dleaf2_split(struct btree *btree, tuxkey_t hint,
			     void *vfrom, void *vinto)
{
	struct dleaf2 *from = vfrom, *into = vinto;
	struct diskextent2 *dex;
	struct extent ex;
	unsigned split_at, count = from_be_u16(from->count);

	/* need 2 extents except sentinel, at least */
	assert(count >= 3);

	/*
	 * Honor hint key, then copy and set new sentinel.
	 */

	dex = dleaf2_lookup_index(btree, from, hint);
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

	from->count = to_be_u16(split_at + 1);		/* +1 for sentinel */
	into->count = to_be_u16(count - split_at);

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
static int dleaf2_merge(struct btree *btree, void *vinto, void *vfrom)
{
	struct dleaf2 *into = vinto, *from = vfrom;
	struct extent into_ex, from_ex;
	unsigned into_count, from_count;
	int can_merge, from_size;

	/* If "from" is empty or sentinel only, does nothing */
	from_count = from_be_u16(from->count);
	if (from_count <= 1)
		return 1;

	from_size = sizeof(from->table[0]) * from_count;
	/* If "into" is empty, just copy. FIXME: why there is no sentinel? */
	into_count = from_be_u16(into->count);
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
	into->count = to_be_u16(into_count + from_count - can_merge);
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
static int dleaf2_chop(struct btree *btree, tuxkey_t start, u64 len, void *leaf)
{
	struct sb *sb = btree->sb;
	struct dleaf2 *dleaf = leaf;
	struct diskextent2 *dex, *dex_limit;
	struct extent ex;
	block_t block;
	int need_sentinel;

	/* FIXME: range chop is unsupported for now */
	assert(len == TUXKEY_LIMIT);

	if (!dleaf->count)
		return 0;

	dex_limit = dleaf->table + from_be_u16(dleaf->count);
	/* Lookup the extent is including index */
	dex = dleaf2_lookup_index(btree, dleaf, start);
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
	dleaf->count = to_be_u16((dex - dleaf->table) + 1 + need_sentinel);

	block = ex.physical + (start - ex.logical);
	dex++;

	while (dex < dex_limit) {
		unsigned count;

		/* Get next diskextent2 */
		get_extent(dex, &ex);
		count = ex.logical - start;
		if (block && count) {
			defer_bfree(&sb->defree, block, count);
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

/* Resize dleaf2 from head */
static void dleaf2_resize(struct dleaf2 *dleaf, struct diskextent2 *head,
			  int diff)
{
	void *limit = dleaf->table + from_be_u16(dleaf->count);

	if (diff == 0)
		return;

	if (diff > 0)
		memmove(head + diff, head, limit - (void *)head);
	else
		memmove(head, head - diff, limit - (void *)(head - diff));
	dleaf->count = to_be_u16(from_be_u16(dleaf->count) + diff);
}

/* Initialize sentinel by bottom key */
static inline void dleaf2_init_sentinel(struct sb *sb, struct dleaf2 *dleaf,
					tuxkey_t key_bottom)
{
	if (!dleaf->count) {
		dleaf->count = to_be_u16(1);
		put_extent(dleaf->table, sb->version, key_bottom, 0);
	}
}

/* Write extents */
static int dleaf2_write(struct btree *btree, tuxkey_t key_bottom,
			tuxkey_t key_limit,
			void *leaf, struct btree_key_range *key,
			tuxkey_t *split_hint)
{
	struct dleaf_req *rq = container_of(key, struct dleaf_req, key);
	struct sb *sb = btree->sb;
	struct dleaf2 *dleaf = leaf;
	struct diskextent2 *dex_start, *dex_end, *dex_limit;
	struct extent ex;
	tuxkey_t limit;
	block_t end_physical;
	unsigned need, between, write_segs, rest_segs;
	int err;

	/* Paranoia checks */
	assert(key->len == seg_total_count(rq->seg + rq->nr_segs,
					   rq->max_segs - rq->nr_segs));

	/*
	 * Overwrite existent diskextent2 by specified segs. To do
	 * it, check existent diskextent2 and resize number of
	 * dleaf->count, then overwrite.
	 *
	 * FIXME: should try to merge at start and last index position.
	 */

	dleaf2_init_sentinel(sb, dleaf, key_bottom);

	limit = key->start + key->len;
	write_segs = rq->max_segs - rq->nr_segs;
	dex_limit = dleaf->table + from_be_u16(dleaf->count);

	need = write_segs + 1;	/* +1 is for sentinel */

	/* Find start of diskextent2 to overwrite */
	dex_start = dleaf2_lookup_index(btree, dleaf, key->start);
	if (dex_start < dex_limit) {
		/* Overwrite only if logical is same with index. */
		get_extent(dex_start, &ex);
		assert(ex.logical <= key->start); /* should have key_bottom */
		if (ex.logical < key->start)
			dex_start++;
	}
	/* How many diskextent2 is needed for head? */
	need += dex_start - dleaf->table;

	/* Find end of diskextent2 to overwrite */
	dex_end = dleaf2_lookup_index(btree, dleaf, limit);
	if (dex_end < dex_limit) {
		if (dex_end < dex_start) {
			/* This is splitting one extent */
			between = 0;
		} else
			between = (dex_end - dex_start) + 1;

		/* Prepare to overwrite end */
		get_extent(dex_end, &ex);
		end_physical = ex.physical;
		if (end_physical)
			end_physical += limit - ex.logical;

		/* How many diskextent2 is needed for tail? */
		need += (dex_limit - dex_end) - 1;
	} else {
		between = dex_end - dex_start;
		/* Write new sentinel */
		end_physical = 0;
	}

	err = 0;
	rest_segs = 0;
	/* Check if we need leaf split */
	if (need > btree->entries_per_leaf) {
		/*
		 * If there is no space, we temporary merge segs as hole.
		 * Then, we overwrite existent diskextent2 now (and it
		 * will be overwritten by real segs after split)
		 * to avoid re-calculate for temporary state.
		 */
		err = -ENOSPC;
		rest_segs = need - btree->entries_per_leaf;
		/* Can we write 1 seg at least? */
		if (rest_segs >= write_segs) {
			/* FIXME: is there better split position? */
			if (dex_start + 1 < dex_limit) {
				get_extent(dex_start + 1, &ex);
				*split_hint = ex.logical;
			} else
				*split_hint = key->start;
			return err;
		}
		/* We can write partially segs and temporary hole */
		write_segs -= rest_segs;
#if 1
		/* Just for debugging */
		need -= rest_segs;
#endif
		/* Reserve space for temporary hole */
		rest_segs++;
	}

	/* Expand/shrink space for segs */
	dleaf2_resize(dleaf, dex_start, (write_segs + 1) - between);
	assert(need == from_be_u16(dleaf->count));

	/* Fill extents */
	while (rq->nr_segs < rq->max_segs - rest_segs) {
		struct seg *seg = rq->seg + rq->nr_segs;

		put_extent(dex_start, sb->version, key->start, seg->block);

		key->start += seg->count;
		key->len -= seg->count;
		rq->nr_segs++;
		dex_start++;
	}
	if (rest_segs) {
		/* Fill as temporary hole */
		put_extent(dex_start, sb->version, key->start, 0);
		dex_start++;

		/* Split at half. FIXME: better split position? */
		get_extent(dleaf->table + from_be_u16(dleaf->count) / 2, &ex);
		*split_hint = ex.logical;
	}
	/* Fill sentinel */
	put_extent(dex_start, sb->version, limit, end_physical);

	return err;
}

/* Read extents */
static int dleaf2_read(struct btree *btree, tuxkey_t key_bottom,
		       tuxkey_t key_limit,
		       void *leaf, struct btree_key_range *key)
{
	struct dleaf_req *rq = container_of(key, struct dleaf_req, key);
	struct dleaf2 *dleaf = leaf;
	struct diskextent2 *dex, *dex_limit;
	struct extent next;
	block_t physical;

	if (rq->nr_segs >= rq->max_segs)
		return 0;

	dex_limit = dleaf->table + from_be_u16(dleaf->count);

	/* Lookup the extent is including index */
	dex = dleaf2_lookup_index(btree, dleaf, key->start);
	if (dex >= dex_limit - 1) {
		/* paranoia check */
		if (dex < dex_limit) {
			get_extent(dex_limit - 1, &next);
			assert(next.physical == 0);
		}
		/* If sentinel, fill by bottom key */
		goto fill_seg;
	}

	/* Get start position of logical and physical */
	get_extent(dex, &next);
	physical = next.physical;
	if (physical)
		physical += key->start - next.logical;	/* add offset */
	dex++;

	do {
		struct seg *seg = rq->seg + rq->nr_segs;

		get_extent(dex, &next);

		/* Check of logical addr range of current and next. */
		seg->count = min_t(u64, key->len, next.logical - key->start);
		if (physical) {
			seg->block = physical;
			seg->state = 0;
		} else {
			seg->block = 0;
			seg->state = SEG_HOLE;
		}

		physical = next.physical;
		key->start += seg->count;
		key->len -= seg->count;
		rq->nr_segs++;
		dex++;
	} while (key->len && rq->nr_segs < rq->max_segs && dex < dex_limit);

fill_seg:
	/* Between sentinel and key_limit is hole */
	if (key->start < key_limit && key->len && rq->nr_segs < rq->max_segs) {
		struct seg *seg = rq->seg + rq->nr_segs;

		seg->count = min_t(tuxkey_t, key->len, key_limit - key->start);
		seg->block = 0;
		seg->state = SEG_HOLE;

		key->start += seg->count;
		key->len -= seg->count;
		rq->nr_segs++;
	}

	return 0;
}

struct btree_ops dtree2_ops = {
	.btree_init	= dleaf2_btree_init,
	.leaf_init	= dleaf2_init,
	.leaf_split	= dleaf2_split,
	.leaf_merge	= dleaf2_merge,
	.leaf_chop	= dleaf2_chop,
	.leaf_write	= dleaf2_write,
	.leaf_read	= dleaf2_read,
	.balloc		= balloc,
	.bfree		= bfree,

	.leaf_sniff	= dleaf2_sniff,
	.leaf_can_free	= dleaf2_can_free,
	.leaf_dump	= dleaf2_dump,
};
