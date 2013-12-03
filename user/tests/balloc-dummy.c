int balloc_from_range(struct sb *sb, block_t start, block_t count,
		      unsigned blocks, unsigned flags,
		      struct block_segment *seg, int segs)
{
	block_t block = sb->nextblock;

	seg->block = block;
	seg->count = blocks;
	seg->state = 0;

	sb->nextblock += blocks;
	trace("-> %Lx/%x", block, blocks);

	return 0;
}

static int __balloc(struct sb *sb, unsigned blocks, unsigned flags,
		    struct block_segment *seg, int segs)
{
	block_t goal = sb->nextblock;
	int err;

	err = balloc_from_range(sb, goal, sb->volblocks, blocks,
				BALLOC_PARTIAL, seg, segs);
	if (err == -ENOSPC) {
		/* FIXME: This is for debugging. Remove this */
		tux3_warn(sb, "couldn't balloc: blocks %u", blocks);
	}

	return err;
}

int balloc(struct sb *sb, unsigned blocks, struct block_segment *seg, int segs)
{
	return __balloc(sb, blocks, 0, seg, segs);
}

#ifndef NO_BALLOC_PARTIAL
int balloc_partial(struct sb *sb, unsigned blocks,
		   struct block_segment *seg, int segs)
{
	return __balloc(sb, blocks, BALLOC_PARTIAL, seg, segs);
}
#endif

int bfree(struct sb *sb, block_t block, unsigned blocks)
{
	trace("<- %Lx/%x", block, blocks);
	return 0;
}

int replay_update_bitmap(struct replay *rp, block_t start, unsigned count,
			 int set)
{
	return 0;
}
