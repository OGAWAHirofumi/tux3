int balloc(struct sb *sb, unsigned blocks, block_t *block)
{
	*block = sb->nextalloc;
	sb->nextalloc += blocks;
	trace("-> %Lx/%x", (L)*block, blocks);
	return 0;
}

int bfree(struct sb *sb, block_t block, unsigned blocks)
{
	trace("<- %Lx/%x", (L)block, blocks);
	return 0;
}
