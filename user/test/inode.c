/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#define trace trace_on

#define main notmain0
#include "balloc.c"
#undef main

#define main notmain1
#include "dleaf.c"
#undef main

#define main notmain2
#include "ileaf.c"
#undef main

#define main notmain3
#include "dir.c"
#undef main

#define main notmain4
#include "btree.c"
#undef main

/* High level operations */

int filemap_blockio(struct buffer *buffer, int write)
{
	struct map *filemap = buffer->map;
	struct inode *inode = filemap->inode;
	struct sb *sb = inode->sb;
	struct map *devmap = sb->devmap;
	struct dev *dev = devmap->dev;
	warn("%s <%Lx:%Lx>", write ? "write" : "read", (L)inode->inum, buffer->index);
	assert(dev->bits >= 9 && dev->fd);

	int err, levels = inode->btree.root.depth;
	struct path path[levels + 1];
	if (!levels) {
		if (write)
			return -EIO;
		goto unmapped;
	}
	if ((err = probe(&inode->btree, buffer->index, path)))
		return err;
	struct buffer *leafbuf = path[levels].buffer;
	
	unsigned count = 0;
	struct extent *found = leaf_lookup(&inode->btree, buffer->index, leafbuf->data, &count);
	//dleaf_dump(&inode->btree, leafbuf->data);
	block_t physical;

	if (write) {
		if (count) {
			physical = found->block;
			trace(warn("found block [%Lx]", (L)physical);)
		} else {
			physical = balloc(sb); // !!! need an error return
			struct extent *store = tree_expand(&inode->btree, buffer->index, sizeof(struct extent), path);
			if (!store)
				goto eek;
			*store = (struct extent){ .block = physical };
		}
		release_path(path, levels + 1);
		return diskwrite(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
	}
	/* read */
	release_path(path, levels + 1);
	if (!count)
		goto unmapped;
	physical = found->block;
	trace(warn("found physical block %Lx", (long long)physical);)
	return diskread(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
eek:
	warn("unable to add extent to tree: %s", strerror(-err));
	free_block(sb, physical);
	return -EIO;
unmapped:
	/* found a hole */
	trace(warn("unmapped block %Lx", buffer->index);)
	memset(buffer->data, 0, sb->blocksize);
	return 0;
}

struct map_ops filemap_ops = { .blockio = filemap_blockio };

struct inode *new_inode(SB, inum_t inum)
{
	struct map *map = new_map(sb->devmap->dev, &filemap_ops);
	struct inode *inode = malloc(sizeof(*inode));
	*inode = (struct inode){ .sb = sb, .map = map, .inum = inum };
	map->inode = inode;
	return inode;
}

void free_inode(struct inode *inode)
{
	free_map(inode->map);
	free(inode);
}

//struct inode *get_inode(SB, inum_t inum, struct buffer **buffer)

struct inode *get_inode(struct inode *inode, struct iattr *iattr)
{
	SB = inode->sb;
	inum_t goal = inode->inum;
	int err = -ENOENT, levels = sb->itree.root.depth;
	struct path path[levels + 1];
	if ((err = probe(&sb->itree, goal, path)))
		return NULL;
	struct buffer *leafbuf = path[levels].buffer;
	unsigned size = 0;
	void *attrs = ileaf_lookup(&sb->itree, goal, leafbuf->data, &size);

	//ileaf_dump(sb, leafbuf->data);
	if (iattr) {
		assert(!inode->btree.root.depth);
		trace(warn("create inode 0x%Lx", (L)goal);)
		/*
		 * If not at end then next key is greater than goal.  This
		 * block has the highest ibase less than or equal to goal.
		 * Ibase should be equal to btree key, so assert.  Search block
		 * even if base inum is way too low.  Whatever inum comes back
		 * from the search (it will be above the highest inum in the
		 * block if base was too low) expand that empty inum.  If ibase
		 * was too low, low level split will fail and expand will create
		 * a new inode table block with ibase at the goal.  Need some
		 * way to verify that expanded inum was empty, pass size by ref?
		 */
		goal = find_empty_inode(&sb->itree, leafbuf->data, goal);
		/*
		 * Need to search following blocks if goal is next_key.  Should
		 * never be greater, assert.
		 */
		assert(goal < next_key(path, levels));

		size = howbig((u8[]){ MODE_OWNER_ATTR, DATA_BTREE_ATTR }, 2);
		void *base = attrs = tree_expand(&sb->itree, goal, size, path);
		if (!attrs)
			goto eek; // what was the error???
		inode->btree = new_btree(sb, &dtree_ops); // error???
		attrs = encode_owner(sb, attrs, iattr->mode, iattr->uid, iattr->gid);
		attrs = encode_btree(sb, attrs, &inode->btree.root);
		assert(attrs - base == size);
		goto out; // !!! load iattrs into inode
	}
	if (size) {
		trace(warn("found inode 0x%Lx", (L)goal);)
		hexdump(attrs, size);
		/* may have to expand */
		// inode = do we have to have an inode/dentry cache now?
		goto out;
	}
	trace(warn("no inode 0x%Lx", (L)goal);)
	err = -ENOENT;
eek:
	err = -EINVAL;
out:
	release_path(path, levels + 1);
	return inode;
}

int tuxread(struct file *file, char *data, unsigned len)
{
	loff_t pos = file->f_pos;
	struct inode *inode = file->f_inode;
	if (pos > inode->i_size)
		return 0;
	if (inode->i_size < pos + len)
		len = inode->i_size - pos;
	warn("read %Lx/%x", (L)(pos & inode->sb->blockmask), len);
	struct buffer *blockbuf = getblk(inode->map, pos >> inode->sb->blockbits);
	if (!blockbuf)
		return -EIO;
	memcpy(data, blockbuf->data + (pos & inode->sb->blockmask), len);
	brelse(blockbuf);
	file->f_pos += len;
	return len;
}

int tuxwrite(struct file *file, char *data, unsigned len)
{
	loff_t pos = file->f_pos;
	struct inode *inode = file->f_inode;
	//warn("write %Lx/%x", pos & inode->sb->blockmask, len);
	struct buffer *blockbuf = getblk(inode->map, pos >> inode->sb->blockbits);
	if (!blockbuf)
		return -EIO;
	memcpy(blockbuf->data + (pos & inode->sb->blockmask), data, len);
	set_buffer_dirty(blockbuf);
	brelse(blockbuf);
	file->f_pos += len;
	if (inode->i_size < file->f_pos)
		inode->i_size = file->f_pos;
	return len;
}

void tuxseek(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

int purge_inum(BTREE, inum_t inum)
{
	int err = -ENOENT, levels = btree->sb->itree.root.depth;
	struct path path[levels + 1];
	if (!(err = probe(btree, inum, path))) {
		err = ileaf_purge(btree, inum, to_ileaf(path[levels].buffer));
		release_path(path, levels + 1);
	}
	return err;
}

struct inode *tuxopen(struct inode *dir, char *name, int len)
{
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (!buffer)
		return NULL;
	inum_t inum = entry->inum;
	brelse(buffer);
	return get_inode(new_inode(dir->sb, inum), NULL);
}

struct inode *tuxcreate(struct inode *dir, char *name, int len, struct iattr *iattr)
{
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (entry) {
		brelse(buffer);
		return NULL; // err_ptr(-EEXIST) ???
	}
	struct inode *inode = get_inode(new_inode(dir->sb, dir->sb->nextalloc), iattr);
	if (!inode)
		return NULL; // err ???
	if (!ext2_create_entry(dir, name, len, inode->inum, iattr->mode))
		return inode;
	purge_inum(&dir->sb->itree, inode->inum); // test me!!!
	free_inode(inode);
	inode = NULL;
	return NULL; // err ???
}

void tuxsync(struct inode *inode)
{
	int err = flush_buffers(inode->map);
	if (err)
		warn("Sync failed (%s)", strerror(-err));
	//encode_csize(sb, attrs, 0, inode->i_size);
}

void tuxclose(struct inode *inode)
{
	tuxsync(inode);
	free_inode(inode);
}

void init_tux3(SB) // why am I separate?
{
	struct inode *bitmap = new_inode(sb, -1);
	sb->bitmap = bitmap;
	sb->super.blockbits = sb->devmap->dev->bits;
	sb->blocksize = 1 << sb->super.blockbits;
	sb->itree = new_btree(sb, &itree_ops);
	sb->itree.entries_per_leaf = 64; // !!! should depend on blocksize
	bitmap->btree = new_btree(sb, &dtree_ops);
}

int main(int argc, char *argv[])
{
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	printf("fd '%s' = %i (0x%Lx bytes)\n", name, fd, (L)size);

	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	struct map *map = new_map(dev, NULL);
	struct sb *sb = &(struct sb){
		.super = { .magic = SB_MAGIC, .blocks = size >> dev->bits },
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = map,
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.nextalloc = 0x40,
	};

	init_buffers(dev, 1 << 20);
	init_tux3(sb);

	struct inode *root = get_inode(new_inode(sb, 100), &(struct iattr){ .mode = S_IFREG | S_IRWXU });
	struct inode *inode = tuxcreate(root, "foo", 3, &(struct iattr){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		return 1;
	ext2_dump_entries(getblk(root->map, 0), sb->blocksize);

	tuxsync(root);
	char buf[100] = { };
	struct file *file = &(struct file){ .f_inode = inode };
	tuxwrite(file, "hello ", 6);
	tuxwrite(file, "world!", 6);
	tuxsync(inode);
	tuxsync(sb->bitmap);
	flush_buffers(sb->devmap);

	tuxseek(file, 0);
	int got = tuxread(file, buf, sizeof(buf));
	//printf("got %x bytes\n", got);
	if (got < 0)
		return 1;
	hexdump(buf, got);
	show_buffers(inode->map);
	show_buffers(root->map);
	show_buffers(sb->devmap);
	bitmap_dump(sb->bitmap, 0, sb->super.blocks);
	show_tree_range(&sb->itree, 0, -1);
	return 0;
}
