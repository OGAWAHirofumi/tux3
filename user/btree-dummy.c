static struct btree_ops dtree_ops;
static void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops)
{
	btree->sb = sb;
	btree->root = root;
	btree->ops = ops;
	btree->entries_per_leaf = 0;
}
