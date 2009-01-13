int balloc(struct sb *sb, unsigned blocks, block_t *block)
{
	trace("-> %Lx\n", (L)sb->nextalloc);
	*block = sb->nextalloc += blocks;
	return 0;
}

int bfree(struct sb *sb, block_t block, unsigned blocks)
{
	trace("<- %Lx, count %x\n", (L)block, blocks);
	return 0;
}
