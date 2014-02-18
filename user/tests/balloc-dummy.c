/*
 * Note: balloc-dummy.c must define all exported functions in balloc.c,
 * otherwise balloc.o will be linked
 */

void countmap_put(struct countmap_pin *countmap_pin)
{
}

int balloc_find_range(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	block_t start, block_t range, unsigned *blocks)
{
	assert(*segs < maxsegs);

	seg[*segs].block = sb->nextblock;
	seg[*segs].count = *blocks;
	seg[*segs].state = 0;
	trace("-> %Lx/%x", seg[*segs].block, seg[*segs].count);
	(*segs)++;
	*blocks = 0;
	return 0;
}

#ifndef NO_BALLOC_FIND
int balloc_find(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	unsigned *blocks)
{
	*segs = 0;
	return balloc_find_range(sb, seg, maxsegs, segs, 0, sb->volblocks,
				 blocks);
}
#endif

int balloc_use(struct sb *sb, struct block_segment *seg, int segs)
{
	block_t goal = seg[segs - 1].block + seg[segs - 1].count;
	sb->nextblock = goal == sb->volblocks ? 0 : goal;
	return 0;
}

int balloc_segs(struct sb *sb,
	struct block_segment *seg, int maxsegs, int *segs,
	unsigned *blocks)
{
	int err = balloc_find(sb, seg, maxsegs, segs, blocks);
	if (!err)
		err = balloc_use(sb, seg, *segs);
	return err;
}

block_t balloc_one(struct sb *sb)
{
	struct block_segment seg;
	unsigned blocks = 1;
	int err, segs;

	err = balloc_segs(sb, &seg, 1, &segs, &blocks);
	if (err)
		return err;
	assert(segs == 1 && blocks == 0 && seg.count == 1);
	return seg.block;
}

int bfree(struct sb *sb, block_t block, unsigned blocks)
{
	trace("<- %Lx/%x", block, blocks);
	return 0;
}

int bfree_segs(struct sb *sb, struct block_segment *seg, int segs)
{
	int i;
	for (i = 0; i < segs; i++)
		bfree(sb, seg[i].block, seg[i].count);
	return 0;
}

int replay_update_bitmap(struct replay *rp, block_t start, unsigned count,
			 int set)
{
	return 0;
}
