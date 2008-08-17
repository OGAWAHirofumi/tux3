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
	warn("%s <%Lx:%Lx>", write ? "write" : "read", inode->inum, buffer->index);
	assert(dev->bits >= 9 && dev->fd);

	int err, levels = inode->root.levels;
	struct treepath path[levels + 1];
	if (!levels) {
		if (!write)
			goto unmapped;
		return -EIO;
	}
	if ((err = probe(sb, &inode->root, buffer->index, path, &dtree_ops)))
		return err;
	struct buffer *leafbuf = path[levels].buffer;
	
	unsigned count = 0;
	struct extent *found = leaf_lookup(sb, leafbuf->data, buffer->index, &count);
	leaf_dump(sb, leafbuf->data);
	block_t physical;

	if (write) {
		if (count) {
			physical = found->block;
			trace(warn("found physical block %Lx", (long long)physical);)
		} else {
			physical = balloc(sb); // !!! need an error return
			trace(warn("new physical block %Lx", physical);)
			struct extent *store = tree_expand(sb, &sb->image.iroot, buffer->index, sizeof(struct extent), path, levels, &dtree_ops);
			if (!store)
				goto eek;
			*store = (struct extent){ .block = physical };
		}
		brelse_path(path, levels);
		return diskwrite(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
	}
	/* read */
	brelse_path(path, levels);
	if (!count)
		goto unmapped;
	physical = found->block;
	trace(warn("found physical block %Lx", (long long)physical);)
	return diskread(dev->fd, buffer->data, sb->blocksize, physical << dev->bits);
eek:
	warn("unable to add extent to tree: %s", strerror(-err));
	free_block(sb, physical);
	brelse_path(path, levels);
	return -EIO;
unmapped:
	/* found a hole */
	trace(warn("unmapped block %Lx", buffer->index);)
	memset(buffer->data, 0, sb->blocksize);
	return 0;
}

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

struct inode *open_inode(SB, inum_t inum, struct create *create)
{
	int err, levels = sb->image.iroot.levels;
	struct treepath path[levels + 1];
	if ((err = probe(sb, &sb->image.iroot, inum, path, &itree_ops)))
		return NULL;
	struct buffer *leafbuf = path[levels].buffer;
	
	struct inode *inode = NULL;
	unsigned size = 0;
	void *ibase = ileaf_lookup(sb, leafbuf->data, inum, &size);
	//ileaf_dump(sb, leafbuf->data);

	if (size) {
		trace(warn("found inode 0x%Lx", inum);)
		hexdump(ibase, size);
		/* may have to expand */
	} else {
		trace(warn("no inode 0x%Lx", inum);)
		if (!create) {
			err = -ENOENT;
			goto eek;
		}
		trace(warn("new inode 0x%Lx", inum);)
		size = sizeof(struct size_mtime_attr) + sizeof(struct data_btree_attr);
		ibase = tree_expand(sb, &sb->image.iroot, inum, size, path, levels, &itree_ops);
		if (!ibase) {
			err = -EINVAL;
			goto eek;
		}

		inode = new_inode(sb, inum, create);

		struct buffer *rootbuf = new_node(sb, &dtree_ops);
		struct buffer *leafbuf = new_leaf(sb, &dtree_ops);
		init_btree(rootbuf->data, leafbuf->index);
		inode->root = (struct btree){ .index = rootbuf->index, .levels = 1 };
		printf("droot at %Li\n", rootbuf->index);
		printf("dleaf at %Li\n", leafbuf->index);
		brelse_dirty(rootbuf);
		brelse_dirty(leafbuf);

		struct size_mtime_attr attr1 = { .kind = MTIME_SIZE_ATTR };
		struct data_btree_attr attr2 = { .kind = DATA_BTREE_ATTR, .btree = inode->root };
		*(typeof(attr1) *)ibase = attr1;
		*(typeof(attr2) *)(ibase + sizeof(attr2)) = attr2;
	}
eek:
	brelse_path(path, levels);
	return inode;
}

void init_tux3(SB)
{
	struct inode *bitmap = new_inode(sb, -1, &(struct create){ .mode = S_IFREG | S_IRWXU });
	sb->bitmap = bitmap;
	sb->image.blockbits = sb->devmap->dev->bits;
	sb->blocksize = 1 << sb->image.blockbits;

	struct buffer *rootbuf = new_node(sb, &itree_ops);
	struct buffer *leafbuf = new_leaf(sb, &itree_ops);
	init_btree(rootbuf->data, leafbuf->index);
	sb->image.iroot = (struct btree){ .index = rootbuf->index, .levels = 1 };
	printf("iroot at %Lx\n", rootbuf->index);
	printf("ileaf at %Lx\n", leafbuf->index);
	brelse_dirty(rootbuf);
	brelse_dirty(leafbuf);
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

int main(int argc, char *argv[])
{
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	size_t size = fdsize64(fd);
	printf("fd '%s' = %i (0x%zx bytes)\n", name, fd, size);

	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	struct map *map = new_map(dev, NULL);

	struct sb *sb = &(struct sb){
		.image = { .magic = SB_MAGIC, .blocks = size >> dev->bits },
		.alloc_per_node = 20,
		.devmap = map,
	};

	init_buffers(dev, 1 << 20);
	init_tux3(sb);

	struct inode *root = open_inode(sb, 0, &(struct create){ .mode = S_IFDIR | S_IRWXU });

	struct inode *inode = tuxopen(root, "foo", 3, 5, &(struct create){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		return 1;
	ext2_dump_entries(getblk(root->map, 0), 1 << map->dev->bits);

	flush_buffers(root->map);
	show_buffers(root->map);
	show_buffers(sb->devmap);

	char buf[100] = { };
	tuxwrite(inode, 6, "hello", 5);
	tuxwrite(inode, 5, "world", 5);
	flush_buffers(sb->devmap);
	flush_buffers(inode->map);
	int err = flush_buffers(sb->bitmap->map);
	if (err)
		warn("Bitmap flush failed (%s)", strerror(-err));
	if (tuxread(inode, 6, buf, 11))
		return 1;
	hexdump(buf, 11);
	if (tuxread(inode, 5, buf, 11))
		return 1;
	hexdump(buf, 11);
	return 0;
}
