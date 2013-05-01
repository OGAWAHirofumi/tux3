#ifndef TUX3_DLEAF2_H
#define TUX3_DLEAF2_H

#define SEG_HOLE	(1 << 0)
#define SEG_NEW		(1 << 1)

struct seg {
	block_t block;
	unsigned count;
	unsigned state;
};

struct dleaf_req {
	struct btree_key_range key;	/* index and count */

	int nr_segs;		/* For read:  how many segs was read.
				 * For write: how many segs was written. */
	int max_segs;		/* For read:  how many seg[] are available
				 * For write: how many seg[] to write */
	struct seg *seg;	/* pointer to seg[] */

	/* Callback to allocate blocks to ->seg for write */
	int (*seg_alloc)(struct btree *, struct dleaf_req *, int);
};

static inline unsigned seg_total_count(struct seg *seg, int nr_segs)
{
	unsigned total = 0;
	int i;
	for (i = 0; i < nr_segs; i++)
		total += seg[i].count;
	return total;
}

#endif /* !TUX3_DLEAF2_H */
