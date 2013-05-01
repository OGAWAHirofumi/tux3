#ifndef TUX3_DLEAF2_H
#define TUX3_DLEAF2_H

struct dleaf_req {
	struct btree_key_range key;	/* index and count */

	int nr_segs;		/* For read:  how many segs was read.
				 * For write: how many segs was written. */
	int max_segs;		/* For read:  how many seg[] are available
				 * For write: how many seg[] to write */
	struct block_segment *seg;	/* pointer to seg[] */

	/* Callback to allocate blocks to ->seg for write */
	int (*seg_alloc)(struct btree *, struct dleaf_req *, int);
};

static inline unsigned seg_total_count(struct block_segment *seg, int nr_segs)
{
	unsigned total = 0;
	int i;
	for (i = 0; i < nr_segs; i++)
		total += seg[i].count;
	return total;
}

#endif /* !TUX3_DLEAF2_H */
