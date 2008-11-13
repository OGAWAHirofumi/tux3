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

#ifndef trace
#define trace trace_on
#endif

#define filemap_included
#include "filemap.c"
#undef main

struct inode *new_inode(SB, inum_t inum)
{
	struct map *map = new_map(sb->devmap->dev, &filemap_ops);
	if (!map)
		goto eek;
	struct inode *inode = malloc(sizeof(*inode));
	if (!inode)
		goto eek;
	*inode = (struct inode){ .sb = sb, .map = map, .inum = inum };
	return inode->map->inode = inode;
eek:
	if (map)
		free_map(map);
	return NULL;
}

void free_inode(struct inode *inode)
{
	assert(inode->map); /* some inodes are not malloced */
	free_map(inode->map); // invalidate dirty buffers!!!
	if (inode->xcache)
		free(inode->xcache);
	free(inode);
}

int store_attrs(SB, struct path *path, struct inode *inode)
{
	unsigned size = encode_asize(inode->present) + encode_xsize(inode);
	void *base = tree_expand(&sb->itable, inode->inum, size, path);
	if (!base)
		return -ENOMEM; // what was the actual error???
	void *attr = encode_attrs(inode, base, size);
	attr = encode_xattrs(inode, attr, base + size - attr);
	assert(attr == base + size);
	return 0;
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
	int err = -ENOENT, levels = sb->itable.root.depth;
	struct path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, inode->inum, path))) {
		free_path(path);
		return err;
	}
	struct buffer *leafbuf = path[levels].buffer;
	struct ileaf *leaf = to_ileaf(leafbuf->data);

	trace("create inode 0x%Lx", (L)inode->inum);
	assert(!inode->btree.root.depth);
	inum_t inum = inode->inum;
	assert(inum < next_key(path, levels));
	while (1) {
		printf("find empty inode in [%Lx] base %Lx\n", (L)leafbuf->index, (L)leaf->ibase);
		inum = find_empty_inode(&sb->itable, leafbuf->data, (L)inum);
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
	inode->i_mtime = inode->i_ctime = inode->i_atime = iattr->ctime;
	inode->i_links = 1;
	inode->btree = new_btree(sb, &dtree_ops); // error???
	inode->present = CTIME_SIZE_BIT|MODE_OWNER_BIT|DATA_BTREE_BIT;
	if ((err = store_attrs(sb, path, inode)))
		goto eek;
	release_path(path, levels + 1);
	free_path(path);
	return 0;
eek:
	release_path(path, levels + 1);
errout:
	free_path(path);
	warn("make_inode 0x%Lx failed (%s)", (L)inode->inum, strerror(-err));
	return err;
}

int open_inode(struct inode *inode)
{
	SB = inode->sb;
	int err, levels = sb->itable.root.depth;
	struct path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, inode->inum, path))) {
		free_path(path);
		return err;
	}
	unsigned size;
	void *attrs = ileaf_lookup(&sb->itable, inode->inum, path[levels].buffer->data, &size);
	if (!attrs) {
		err = -ENOENT;
		goto eek;
	}
	trace("found inode 0x%Lx", (L)inode->inum);
	//ileaf_dump(&sb->itable, path[levels].buffer->data);
	//hexdump(attrs, size);
	unsigned xsize = decode_xsize(inode, attrs, size);
	err = -ENOMEM;
	if (!(inode->xcache = new_xcache(xsize))) // !!! only do this when we hit an xattr !!!
		goto eek;
	decode_attrs(inode, attrs, size); // error???
	dump_attrs(inode);
	if (inode->xcache)
		xcache_dump(inode);
	err = 0;
eek:
	release_path(path, levels + 1);
	free_path(path);
	return err;
}

int save_inode(struct inode *inode)
{
	trace("save inode 0x%Lx", (L)inode->inum);
	SB = inode->sb;
	int err, levels = sb->itable.root.depth;
	struct path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, inode->inum, path))) {
		free_path(path);
		return err;
	}
	unsigned size;
	if (!(ileaf_lookup(&sb->itable, inode->inum, path[levels].buffer->data, &size)))
		return -EINVAL;
	if (inode->i_size)
		inode->present |= CTIME_SIZE_BIT;
	err = store_attrs(sb, path, inode);
	release_path(path, levels + 1);
	free_path(path);
	return err;
}

int tuxio(struct file *file, char *data, unsigned len, int write)
{
	int err = 0;
	struct inode *inode = file->f_inode;
	loff_t pos = file->f_pos;
	trace("%s %u bytes at %Lu, isize = 0x%Lx", write ? "write" : "read", len, pos, (L)inode->i_size);
	if (write && pos + len > MAX_FILESIZE)
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
			err = -EIO;
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
	return err ? err : len - tail;
}

int tuxread(struct file *file, char *data, unsigned len)
{
	return tuxio(file, data, len, 0);
}

int tuxwrite(struct file *file, const char *data, unsigned len)
{
	return tuxio(file, (void *)data, len, 1);
}

void tuxseek(struct file *file, loff_t pos)
{
	warn("seek to 0x%Lx", (L)pos);
	file->f_pos = pos;
}

int purge_inum(BTREE, inum_t inum)
{
	int err = -ENOENT, levels = btree->sb->itable.root.depth;
	struct path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if (!(err = probe(btree, inum, path))) {
		struct ileaf *ileaf = to_ileaf(path[levels].buffer->data);
		err = ileaf_purge(btree, inum, ileaf);
		release_path(path, levels + 1);
	}
	free_path(path);
	return err;
}

struct inode *tuxopen(struct inode *dir, const char *name, int len)
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

struct inode *tuxcreate(struct inode *dir, const char *name, int len, struct iattr *iattr)
{
	iattr->ctime = tuxtime();

	struct buffer *buffer;
	ext2_dirent *entry = ext2_find_entry(dir, name, len, &buffer);
	if (entry) {
		brelse(buffer);
		return NULL; // should allow create of a file that already exists
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
	if (ext2_create_entry(dir, name, len, inode->inum, iattr->mode) >= 0)
		return inode;
	purge_inum(&dir->sb->itable, inode->inum); // test me!!!
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
	if (memcmp(disk->magic, (char[])SB_MAGIC, sizeof(disk->magic))) {
		warn("invalid superblock [%Lx]", (L)from_be_u64(*(u64 *)disk->magic));
		return -ENOENT;
	}
	int blockbits = from_be_u16(disk->blockbits);
	sb->volblocks = from_be_u64(disk->volblocks);
	sb->nextalloc = from_be_u64(disk->nextalloc);
	sb->atomgen = from_be_u32(disk->atomgen);
	sb->freeatom = from_be_u32(disk->freeatom);
	sb->freeblocks = from_be_u64(disk->freeblocks);
	u64 iroot = from_be_u64(disk->iroot);
	sb->itable.root = (struct root){ .depth = iroot >> 48, .block = iroot & (-1ULL >> 16) };
	sb->blockbits = blockbits,
	sb->blocksize = 1 << blockbits,
	sb->blockmask = (1 << blockbits) - 1,
	sb->devmap->dev->bits = blockbits;
	//hexdump(&sb->super, sizeof(sb->super));
	return 0;
}

int save_sb(SB)
{
	struct disksuper *disk = &sb->super;
	disk->blockbits = to_be_u16(sb->devmap->dev->bits);
	disk->volblocks = to_be_u64(sb->volblocks);
	disk->nextalloc = to_be_u64(sb->nextalloc); // probably does not belong here
	disk->freeatom = to_be_u32(sb->freeatom); // probably does not belong here
	disk->atomgen = to_be_u32(sb->atomgen); // probably does not belong here
	disk->freeblocks = to_be_u64(sb->freeblocks); // probably does not belong here
	disk->iroot = to_be_u64((u64)sb->itable.root.depth << 48 | sb->itable.root.block);
	//hexdump(&sb->super, sizeof(sb->super));
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
	printf("sync atom table\n");
	if ((err = tuxsync(sb->atable)))
		return err;
	printf("sync devmap\n");
	if ((err = flush_buffers(sb->devmap)))
		return err;
	printf("sync super\n");
	if ((err = save_sb(sb)))
		return err;
	return 0;
}

int make_tux3(SB, int fd)
{
	int err = 0;
	trace("create bitmap");
	if (!(sb->bitmap = new_inode(sb, 0)))
		goto eek;

	trace("reserve superblock");
	/* Always 8K regardless of blocksize */
	int reserve = 1 << (sb->blockbits > 13 ? 0 : 13 - sb->blockbits);
	for (int i = 0; i < reserve; i++)
		trace("reserve %Lx", (L)balloc_from_range(sb->bitmap, i, 1)); // error ???

	trace("create inode table");
	sb->itable = new_btree(sb, &itable_ops);
	if (!sb->itable.ops)
		goto eek;
	sb->itable.entries_per_leaf = 64; // !!! should depend on blocksize
	sb->bitmap->i_size = (sb->volblocks + 7) >> 3;
	trace("create bitmap inode");
	if (make_inode(sb->bitmap, &(struct iattr){ }))
		goto eek;
	trace("create version table");
	if (!(sb->vtable = new_inode(sb, 0x2)))
		goto eek;
	if (make_inode(sb->vtable, &(struct iattr){ }))
		goto eek;
	trace("create root directory");
	if (!(sb->rootdir = new_inode(sb, 0xd)))
		goto eek;
	if (make_inode(sb->rootdir, &(struct iattr){ .mode = S_IFDIR | 0755 }))
		goto eek;
	trace("create atom dictionary");
	if (!(sb->atable = new_inode(sb, 0xa)))
		goto eek;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->unatom_base + (1 << (34 - sb->blockbits));
	sb->atomgen = 1; // atom 0 not allowed, means end of atom freelist
	if (make_inode(sb->atable, &(struct iattr){ }))
		goto eek;
	if ((err = sync_super(sb)))
		goto eek;

	show_buffers(sb->bitmap->map);
	show_buffers(sb->rootdir->map);
	show_buffers(sb->devmap);
	return 0;
eek:
	free_btree(&sb->itable);
	free_inode(sb->bitmap);
	sb->bitmap = NULL;
	sb->itable = (struct btree){ };
	if (err) {
		warn("eek, %s", strerror(-err));
		return err;
	}
	return -ENOSPC; // just guess
}

#ifndef include_inode_c
int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
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

	trace("make tux3 filesystem on %s (0x%Lx bytes)", name, (L)size);
	if ((errno = -make_tux3(sb, fd)))
		goto eek;
	trace("create file");
	struct inode *inode = tuxcreate(sb->rootdir, "foo", 3, &(struct iattr){ .mode = S_IFREG | S_IRWXU });
	if (!inode)
		return 1;
	ext2_dump_entries(getblk(sb->rootdir->map, 0));

	trace(">>> write file");
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
	trace(">>> close file <<<");
	set_xattr(inode, "foo", 5, "hello world!", 12);
	save_inode(inode);
	tuxclose(inode);
	trace(">>> open file");
	file = &(struct file){ .f_inode = tuxopen(sb->rootdir, "foo", 3) };
	inode = file->f_inode;
	xcache_dump(inode);
#endif
	trace(">>> read file");
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	memset(buf, 0, sizeof(buf));
	int got = tuxread(file, buf, sizeof(buf));
	trace_off("got %x bytes", got);
	if (got < 0)
		return 1;
	hexdump(buf, got);
	trace(">>> show state");
	show_buffers(file->f_inode->map);
	show_buffers(sb->rootdir->map);
	show_buffers(sb->devmap);
	bitmap_dump(sb->bitmap, 0, sb->volblocks);
	show_tree_range(&sb->itable, 0, -1);
	return 0;
eek:
	return error("Eek! %s", strerror(errno));
}
#endif
