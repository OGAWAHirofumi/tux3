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
	if (buffer->index & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	assert(dev->bits >= 8 && dev->fd);

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
	free_map(inode->map); // invalidate dirty buffers!!!
	free(inode);
}

/*
 * Inode table expansion algorithm
 *
 * First probe for the inode goal.  This retreives the rightmost leaf that
 * contains an inode less than or equal to the goal.  (We could in theory avoid
 * retrieving any leaf at all in some cases if we observe that the the goal must
 * fall into an unallocated gap between two index keys, for what that is worth.
 * Probably not very much.)
 *
 * If not at end then next key is greater than goal.  This block has the highest
 * ibase less than or equal to goal.  Ibase should be equal to btree key, so
 * assert.  Search block even if ibase is way too low.  If goal comes back equal
 * to next_key then there is no room to create more inodes in it, so advance to
 * the next block and repeat.
 *
 * Otherwise, expand the inum goal that came back.  If ibase was too low to
 * create the inode in that block then the low level split will fail and expand
 * will create a new inode table block with ibase at the goal.  We round the
 * goal down to some binary multiple in ileaf_split to reduce the chance of
 * creating inode table blocks with only a small number of inodes.  (Actually
 * we should only round down the split point, not the returned goal.)
 */

int make_inode(struct inode *inode, struct iattr *iattr)
{
	SB = inode->sb;
	int err = -ENOENT, levels = sb->itree.root.depth;
	struct path path[levels + 1];
	if ((err = probe(&sb->itree, inode->inum, path)))
		return err;
	struct buffer *leafbuf = path[levels].buffer;
	struct ileaf *leaf = to_ileaf(leafbuf->data);

	trace(warn("create inode 0x%Lx", (L)inode->inum);)
	assert(!inode->btree.root.depth);
	inum_t inum = inode->inum;
	assert(inum < next_key(path, levels));
	while (1) {
		printf("find empty inode in [%Lx] base %Lx\n", (L)leafbuf->index, (L)leaf->ibase);
		inum = find_empty_inode(&sb->itree, leafbuf->data, (L)inum);
		printf("result inum is %Lx, limit is %Lx\n", (L)inum, (L)next_key(path, levels));
		if (inum < next_key(path, levels))
			break;
		int more = advance(leafbuf->map, path, levels);
		printf("no more inode space here, advance %i\n", more);
		if (!more)
			goto errout;
	}
	inode->inum = inum;
	inode->i_mode = iattr->mode;
	inode->i_uid = iattr->uid;
	inode->i_gid = iattr->gid;
	inode->i_mtime = inode->i_ctime = inode->i_atime = iattr->mtime;
	inode->i_links = 1;
	inode->btree = new_btree(sb, &dtree_ops); // error???
	inode->present = MODE_OWNER_BIT|DATA_BTREE_BIT;
	unsigned size = howbig(MODE_OWNER_BIT|DATA_BTREE_BIT);
	void *base = tree_expand(&sb->itree, inum, size, path);
	if (!base)
		goto errmem; // what was the error???
	void *attrs = encode_attrs(sb, base, size, inode);
	assert(attrs == base + size);
	release_path(path, levels + 1);
	return 0;
errmem:
	err = -ENOMEM;
	release_path(path, levels + 1);
errout:
	warn("make_inode 0x%Lx failed (%s)", (L)inode->inum, strerror(-err));
	return err;
}

int open_inode(struct inode *inode)
{
	SB = inode->sb;
	int err, levels = sb->itree.root.depth;
	struct path path[levels + 1];
	if ((err = probe(&sb->itree, inode->inum, path)))
		return err;
	unsigned size;
	void *attrs = ileaf_lookup(&sb->itree, inode->inum, path[levels].buffer->data, &size);
	if (!attrs) {
		err = -ENOENT;
		goto eek;
	}
	trace(warn("found inode 0x%Lx", (L)inode->inum);)
	//ileaf_dump(&sb->itree, path[levels].buffer->data);
	//hexdump(attrs, size);
	decode_attrs(sb, attrs, size, inode);
	dump_attrs(sb, inode);
	err = 0;
eek:
	release_path(path, levels + 1);
	return err;
}

int save_inode(struct inode *inode)
{
	trace(warn("save inode 0x%Lx", (L)inode->inum);)
	SB = inode->sb;
	int err, levels = sb->itree.root.depth;
	struct path path[levels + 1];
	if ((err = probe(&sb->itree, inode->inum, path)))
		return err;
	unsigned size;
	void *base = ileaf_lookup(&sb->itree, inode->inum, path[levels].buffer->data, &size);
	if (!size)
		return -EINVAL;
	if (inode->i_size)
		inode->present |= CTIME_SIZE_BIT;
	size = howbig(inode->present);
	base = tree_expand(&sb->itree, inode->inum, size, path); // error???
	void *attrs = encode_attrs(sb, base, size, inode);
	assert(attrs == base + size);
	release_path(path, levels + 1);
	dump_attrs(sb, inode);
	return 0;
}

int tuxio(struct file *file, char *data, unsigned len, int write)
{
	struct inode *inode = file->f_inode;
	printf("%s %u bytes, isize = 0x%Lx\n", write ? "write" : "read", len, (L)inode->i_size);
	loff_t pos = file->f_pos;
	if (pos + len > MAX_FILESIZE)
		return -EFBIG;
	if (!write && pos + len > inode->i_size) {
		if (pos >= inode->i_size)
			return 0;
		len = inode->i_size - pos;
	}
	unsigned bbits = inode->sb->blockbits;
	unsigned bsize = inode->sb->blocksize;
	unsigned bmask = inode->sb->blockmask;
	loff_t tail = len;
	while (tail) {
		unsigned from = pos & bmask;
		unsigned some = from + tail > bsize ? bsize - from : tail;
		int full = write && some == bsize;
		struct buffer *buffer = (full ? getblk : bread)(inode->map, pos >> bbits);
		if (!buffer) {
			errno = EIO;
			break;
		}
		if (write)
			memcpy(buffer->data + from, data, some);
		else
			memcpy(data, buffer->data + from, some);
		printf("transfer %u bytes, block 0x%Lx, buffer %p\n", some, (L)buffer->index, buffer);
		hexdump(buffer->data + from, some);
		set_buffer_dirty(buffer);
		brelse(buffer);
		tail -= some;
		data += some;
		pos += some;
	}
	file->f_pos = pos;
	if (write && inode->i_size < pos)
		inode->i_size = pos;
	return errno ? -errno : len - tail;
}

int tuxread(struct file *file, char *data, unsigned len)
{
	return tuxio(file, data, len, 0);
}

int tuxwrite(struct file *file, char *data, unsigned len)
{
	return tuxio(file, data, len, 1);
}

void tuxseek(struct file *file, loff_t pos)
{
	warn("seek to 0x%Lx", (L)pos);
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
	if (!entry)
		return NULL;
	inum_t inum = entry->inum;
	brelse(buffer);
	struct inode *inode = new_inode(dir->sb, inum);
	return open_inode(inode) ? NULL : inode;
}

struct inode *tuxcreate(struct inode *dir, char *name, int len, struct iattr *iattr)
{
	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (entry) {
		brelse(buffer);
		return NULL; // err_ptr(-EEXIST) ???
	}
	/*
	 * For now the inum allocation goal is the same as the block allocation
	 * goal.  This allows a maximum inum density of one per block and should
	 * give pretty good spacial correlation between inode table blocks and
	 * file data belonging to those inodes provided somebody sets the block
	 * allocation goal based on the directory the file will be in.
	 */
	struct inode *inode = new_inode(dir->sb, dir->sb->nextalloc);
	if (!inode)
		return NULL; // err ???
	int err = make_inode(inode, iattr);
	if (err)
		return NULL; // err ???
	if (!ext2_create_entry(dir, name, len, inode->inum, iattr->mode))
		return inode;
	purge_inum(&dir->sb->itree, inode->inum); // test me!!!
	free_inode(inode);
	inode = NULL;
	return NULL; // err ???
}

int tuxflush(struct inode *inode)
{
	return flush_buffers(inode->map);
}

int tuxsync(struct inode *inode)
{
	tuxflush(inode);
	save_inode(inode);
	return 0; // wrong!!!
}

void tuxclose(struct inode *inode)
{
	tuxsync(inode);
	free_inode(inode);
}

int load_sb(SB)
{
	int err = diskread(sb->devmap->dev->fd, &sb->super, sizeof(struct disksuper), SB_LOC);
	if (err)
		return err;
	struct disksuper *disk = &sb->super;
	sb->devmap->dev->bits = be_to_u16(disk->blockbits);
	sb->volblocks = be_to_u64(disk->volblocks);
	sb->nextalloc = be_to_u64(disk->nextalloc);
	sb->freeblocks = be_to_u64(disk->freeblocks);
	u64 iroot = be_to_u64(disk->iroot);
	sb->itree.root = (struct root){ .depth = iroot >> 48, .block = iroot & (-1ULL >> 16) };
	hexdump(&sb->super, sizeof(sb->super));
	return 0;
}

int save_sb(SB)
{
	struct disksuper *disk = &sb->super;
	disk->blockbits = u16_to_be(sb->devmap->dev->bits);
	disk->volblocks = u64_to_be(sb->volblocks);
	disk->nextalloc = u64_to_be(sb->nextalloc); // probably does not belong here
	disk->freeblocks = u64_to_be(sb->freeblocks); // probably does not belong here
	disk->iroot = u64_to_be((u64)sb->itree.root.depth << 48 | sb->itree.root.block);
	hexdump(&sb->super, sizeof(sb->super));
	return diskwrite(sb->devmap->dev->fd, &sb->super, sizeof(struct disksuper), SB_LOC);
}

int sync_super(SB)
{
	int err;
	printf("sync bitmap\n");
	if ((err = tuxsync(sb->bitmap)))
		return err;
	printf("sync rootdir\n");
	if ((err = tuxsync(sb->rootdir)))
		return err;
	printf("sync devmap\n");
	if ((err = flush_buffers(sb->devmap)))
		return err;
	printf("sync sb\n");
	if ((err = save_sb(sb)))
		return err;
	return 0;
}

int make_tux3(SB, int fd)
{
	printf("---- allocate superblock ----\n");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++)
		printf("reserve %Lx\n", balloc_from_range(sb->bitmap, i, 1));

	printf("---- create inode table ----\n");
	sb->itree = new_btree(sb, &itree_ops);
	if (!sb->itree.ops)
		goto eek;
	sb->itree.entries_per_leaf = 64; // !!! should depend on blocksize
	sb->bitmap->i_size = (sb->volblocks + 7) >> 3;
	if (make_inode(sb->bitmap, &(struct iattr){ }))
		goto eek;
	printf("---- create root ----\n");
	if (!(sb->rootdir = new_inode(sb, 0xd)))
		goto eek;
	make_inode(sb->rootdir, &(struct iattr){ .mode = S_IFREG | S_IRWXU }); // error???

	if (sync_super(sb))
		goto eek;

	show_buffers(sb->bitmap->map);
	show_buffers(sb->rootdir->map);
	show_buffers(sb->devmap);
	return 0;
eek:
	free_btree(&sb->itree);
	free_inode(sb->bitmap);
	sb->bitmap = NULL;
	sb->itree = (struct btree){ };
	return -ENOSPC; // just guess
}

#ifndef included_inode_c
int main(int argc, char *argv[])
{
	int err = 0;
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ fd, .bits = 12 };
	init_buffers(dev, 1 << 20);
	SB = &(struct sb){
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.devmap = new_map(dev, NULL),
		.blockbits = dev->bits,
		.blocksize = 1 << dev->bits,
		.blockmask = (1 << dev->bits) - 1,
		.volblocks = size >> dev->bits,
	};

	sb->bitmap = new_inode(sb, 0);
	if (!sb->bitmap)
		goto eek;

	printf("make tux3 filesystem on %s (0x%Lx bytes)\n", name, (L)size);
	if ((errno = -make_tux3(sb, fd)))
		goto eek;
	printf("---- create file ----\n");
	struct inode *inode = tuxcreate(sb->rootdir, "foo", 3, &(struct iattr){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		return 1;
	ext2_dump_entries(getblk(sb->rootdir->map, 0), sb->blocksize);

	printf("---- write file ----\n");
	char buf[100] = { };
	struct file *file = &(struct file){ .f_inode = inode };
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	err = tuxwrite(file, "hello ", 6);
	err = tuxwrite(file, "world!", 6);
#if 0
	tuxflush(sb->bitmap);
	flush_buffers(sb->devmap);
#endif
#if 1
	printf("---- close file ----\n");
	save_inode(inode);
	tuxclose(inode);
	printf("---- open file ----\n");
	file = &(struct file){ .f_inode = tuxopen(sb->rootdir, "foo", 3) };
#endif

	printf("---- read file ----\n");
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	memset(buf, 0, sizeof(buf));
	int got = tuxread(file, buf, sizeof(buf));
	//printf("got %x bytes\n", got);
	if (got < 0)
		return 1;
	hexdump(buf, got);
	printf("---- show state ----\n");
	show_buffers(file->f_inode->map);
	show_buffers(sb->rootdir->map);
	show_buffers(sb->devmap);
	bitmap_dump(sb->bitmap, 0, sb->volblocks);
	show_tree_range(&sb->itree, 0, -1);
	return 0;
eek:
	fprintf(stderr, "Eek! %s\n", strerror(errno));
	exit(1);
}
#endif
