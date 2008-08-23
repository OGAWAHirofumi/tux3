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

	int err, levels = inode->btree.root.levels;
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

/* this will be iattr.c... */

enum { MTIME_SIZE_ATTR = 8, DATA_BTREE_ATTR = 9 };

struct size_mtime_attr { u64 kind:4, size:60, version:10, mtime:54; };
struct data_btree_attr { u64 kind:4; struct diskroot root; };
struct map_ops filemap_ops = { .blockio = filemap_blockio };
struct create { mode_t mode; unsigned uid, gid; };

struct inode *new_inode(SB, inum_t inum, struct create *create)
{
	struct map *map = new_map(sb->devmap->dev, &filemap_ops);
	struct inode *inode = malloc(sizeof(*inode));
	*inode = (struct inode){ .sb = sb, .inum = inum, .map = map, .i_mode = create->mode };
	map->inode = inode;
	return inode;
}

struct inode *open_inode(SB, inum_t goal, struct create *create)
{
	int err = -ENOENT, levels = sb->itree.root.levels;
	struct path path[levels + 1];
	if ((err = probe(&sb->itree, goal, path)))
		return NULL;
	struct buffer *leafbuf = path[levels].buffer;
	unsigned size = 0;
	void *attrs = ileaf_lookup(&sb->itree, goal, leafbuf->data, &size);
	struct inode *inode = NULL;

	//ileaf_dump(sb, leafbuf->data);
	if (create) {
		trace(warn("new inode 0x%Lx", (L)goal);)
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
		assert(goal < next_key(path, levels));

		size = sizeof(struct size_mtime_attr) + sizeof(struct data_btree_attr);
		attrs = tree_expand(&sb->itree, goal, size, path);
		if (!attrs)
			goto eek; // what was the error???

		inode = new_inode(sb, goal, create);
		inode->btree = new_btree(sb, &dtree_ops);
		struct size_mtime_attr attr1 = { .kind = MTIME_SIZE_ATTR };
		struct data_btree_attr attr2 = { .kind = DATA_BTREE_ATTR, .root = inode->btree.root };
		*(typeof(attr1) *)attrs = attr1;
		*(typeof(attr2) *)(attrs + sizeof(attr1)) = attr2;
		goto out;
	}
	if (size) {
		trace(warn("found inode 0x%Lx", (L)goal);)
		hexdump(attrs, size);
		/* may have to expand */
		// inode = do we have to have an inode/dentry cache now?
		goto out;
	}
	trace(warn("no inode 0x%Lx", (L)goal);)
eek:
	err = -EINVAL;
out:
	release_path(path, levels + 1);
	return inode;
}

int tuxread(struct inode *inode, block_t target, char *data, unsigned len)
{
	struct buffer *blockbuf = bread(inode->map, target);
	if (!blockbuf)
		return -EIO;
	memcpy(data, blockbuf->data, len);
	brelse(blockbuf);
	return 0;
}

int tuxwrite(struct inode *inode, block_t target, char *data, unsigned len)
{
	struct buffer *blockbuf = getblk(inode->map, target);
	if (!blockbuf)
		return -EIO;
	memcpy(blockbuf->data, data, len);
	set_buffer_dirty(blockbuf);
	brelse(blockbuf);
	return 0;
}

void init_tux3(SB)
{
	struct inode *bitmap = new_inode(sb, -1, &(struct create){ .mode = S_IFREG | S_IRWXU });
	sb->bitmap = bitmap;
	sb->image.blockbits = sb->devmap->dev->bits;
	sb->blocksize = 1 << sb->image.blockbits;
	sb->itree = new_btree(sb, &itree_ops);
	bitmap->btree = new_btree(sb, &dtree_ops);
}

struct inode *tuxopen(struct inode *dir, char *name, int len, inum_t inum, struct create *create)
{
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (!create) {
		if (!entry)
			return NULL;
		inum = entry->inode;
		brelse(buffer);
		goto open;
	}
	// !!! choose an inum !!! //
	if (entry) {
		brelse(buffer);
		return NULL;
	}
	if (ext2_create_entry(dir, name, len, inum, create->mode))
		return NULL;
open:
	return open_inode(dir->sb, inum, create);
}

void tuxsync(struct inode *inode)
{
	int err = flush_buffers(inode->map);
	if (err)
		warn("Sync failed (%s)", strerror(-err));
}

void tuxclose(struct inode *inode)
{
	tuxsync(inode);
	free_map(inode->map);
	free(inode);
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
		.image = { .magic = SB_MAGIC, .blocks = size >> dev->bits },
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = map,
	};

	init_buffers(dev, 1 << 20);
	init_tux3(sb);

	struct inode *root = open_inode(sb, 100, &(struct create){ .mode = S_IFDIR | S_IRWXU });
	struct inode *inode = tuxopen(root, "foo", 3, 5, &(struct create){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		return 1;
	ext2_dump_entries(getblk(root->map, 0), 1 << map->dev->bits);

	tuxsync(root);
	char buf[100] = { };
	tuxwrite(inode, 6, "hello", 5);
	tuxwrite(inode, 5, "world", 5);
	tuxsync(inode);
	tuxsync(sb->bitmap);
	flush_buffers(sb->devmap);

	if (tuxread(inode, 6, buf, 11))
		return 1;
	hexdump(buf, 11);
	if (tuxread(inode, 5, buf, 11))
		return 1;
	hexdump(buf, 11);
	show_buffers(inode->map);
	show_buffers(root->map);
	show_buffers(sb->devmap);
	bitmap_dump(sb->bitmap, 0, sb->image.blocks);
	show_tree_range(&sb->itree, 0, -1);
	return 0;
}
