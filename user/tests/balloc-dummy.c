block_t balloc_from_range(struct sb *sb, block_t start, unsigned count, unsigned blocks)
{
	block_t block = sb->nextalloc;
	sb->nextalloc += blocks;
	trace("-> %Lx/%x", block, blocks);
	return block;
}

int balloc(struct sb *sb, unsigned blocks, block_t *block)
{
	block_t goal = sb->nextalloc, total = sb->volblocks;

	if ((*block = balloc_from_range(sb, goal, total - goal, blocks)) >= 0)
		goto found;
	if ((*block = balloc_from_range(sb, 0, goal, blocks)) >= 0)
		goto found;
	return -ENOSPC;
found:
	return 0;
}

int bfree(struct sb *sb, block_t block, unsigned blocks)
{
	trace("<- %Lx/%x", block, blocks);
	return 0;
}
