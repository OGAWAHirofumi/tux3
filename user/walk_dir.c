typedef void (*walk_data_dir_cb)(struct btree *, struct buffer_head *,
				 block_t, struct tux3_dirent *, void *);

static void walk_data_dir(struct btree *btree, struct buffer_head *dleafbuf,
			  struct buffer_head *buffer, block_t block,
			  void *callback_ptr, void *data)
{
	struct sb *sb = btree->sb;
	walk_data_dir_cb callback = callback_ptr;
	struct tux3_dirent *entry = bufdata(buffer);
	struct tux3_dirent *limit = (void *)entry + sb->blocksize;

	while (entry < limit) {
		callback(btree, buffer, block, entry, data);
		entry = (void *)entry + be16_to_cpu(entry->rec_len);
	}
}

static void walk_extent_dir(struct btree *btree, struct buffer_head *dleafbuf,
			    block_t index, block_t block, unsigned count,
			    walk_data_dir_cb callback, void *data)
{
	walk_extent(btree, dleafbuf, index, block, count,
		    walk_data_dir, callback, data);
}

void *unuse_walk_dir = walk_extent_dir; 	/* tux3graph doesn't use this */
