/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#ifndef trace
#define trace trace_on
#endif

#define HASH_SHIFT	10
#define HASH_SIZE	(1 << 10)
#define HASH_MASK	(HASH_SIZE - 1)

static struct hlist_head inode_hashtable[HASH_SIZE] = {
	[0 ... (HASH_SIZE - 1)] = HLIST_HEAD_INIT,
};

static unsigned long hash(inum_t inum)
{
	u64 hash = inum * GOLDEN_RATIO_PRIME;
	return hash >> (64 - HASH_SHIFT);
}

static void insert_inode_hash(struct inode *inode)
{
	struct hlist_head *b = inode_hashtable + hash(inode->inum);
	hlist_add_head(&inode->i_hash, b);
}

static void remove_inode_hash(struct inode *inode)
{
	if (!hlist_unhashed(&inode->i_hash))
		hlist_del_init(&inode->i_hash);
}

static struct inode *new_inode(struct sb *sb)
{
	struct inode *inode = malloc(sizeof(*inode));
	if (!inode)
		goto error;
	*inode = (struct inode){ INIT_INODE(*inode, sb, 0), };
	INIT_HLIST_NODE(&inode->i_hash);
	inode->map = new_map(sb->dev, NULL);
	if (!inode->map)
		goto error_map;
	inode->map->inode = inode;
	return inode;

error_map:
	free(inode);
error:
	return NULL;
}

static void free_inode(struct inode *inode)
{
	assert(list_empty(&inode->alloc_list));
	assert(list_empty(&inode->orphan_list));
	assert(hlist_unhashed(&inode->i_hash));
	assert(list_empty(&inode->list));
	assert(inode->i_state == I_FREEING);
	assert(mapping(inode));

	free_map(mapping(inode));
	free(inode);
}

#include "kernel/inode.c"

static void tux_setup_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	assert(inode->inum != TUX_INVALID_INO);
	switch (inode->inum) {
	case TUX_VOLMAP_INO:
		/* use default handler */
		break;
	case TUX_LOGMAP_INO:
		inode->map->io = dev_errio;
		break;
	case TUX_BITMAP_INO:
		/* set maximum bitmap size */
		/* FIXME: should this, tuxtruncate();? */
		inode->i_size = (sb->volblocks + 7) >> 3;
		/* FALLTHRU */
	default:
		inode->map->io = filemap_extent_io;
		break;
	}
}

static int evict_inode(struct inode *inode)
{
	int err = 0;

	if (inode->i_nlink > 0) {
		truncate_inode_pages(mapping(inode), 0);
		assert(!(inode->i_state & I_DIRTY));
	} else {
		/*
		 * FIXME: since in-core inode is freed, we should do
		 * something for freeing inode even if error happened.
		 */

		err = tuxtruncate(inode, 0);
		if (err)
			goto error;
		/* FIXME: we have to free dtree-root, atable entry, etc too */
		free_empty_btree(&tux_inode(inode)->btree);
		clear_inode(inode);

		err = tux3_clear_inode_orphan(inode);
		if (err)
			goto error;

		err = purge_inode(inode);
		if (err)
			goto error;
	}

error:
	if (inode->xcache)
		free(inode->xcache);

	return err;
}

void iput(struct inode *inode)
{
	if (atomic_dec_and_test(&inode->i_count)) {
		if (inode->i_nlink > 0 && inode->i_state & I_DIRTY) {
			/* Keep the inode on dirty list */
			return;
		}

		inode->i_state |= I_FREEING;
		evict_inode(inode);

		remove_inode_hash(inode);
		free_inode(inode);
	}
}

void __iget(struct inode *inode)
{
	assert(!(inode->i_state & I_FREEING));
	if (atomic_read(&inode->i_count)) {
		atomic_inc(&inode->i_count);
		return;
	}
	/* i_count == 0 should happen only dirty inode */
	assert(inode->i_state & I_DIRTY);
	atomic_inc(&inode->i_count);
}

static struct inode *find_inode(struct sb *sb, inum_t inum)
{
	struct hlist_head *head = inode_hashtable + hash(inum);
	struct hlist_node *node;
	struct inode *inode;

	hlist_for_each_entry(inode, node, head, i_hash) {
		if (inode->inum == inum) {
			__iget(inode);
			return inode;
		}
	}
	return NULL;
}

struct inode *tux3_iget(struct sb *sb, inum_t inum)
{
	struct inode *inode = find_inode(sb, inum);
	if (!inode) {
		inode = new_inode(sb);
		if (!inode)
			return ERR_PTR(-ENOMEM);
		tux_set_inum(inode, inum);
		insert_inode_hash(inode);

		int err = open_inode(inode);
		if (err) {
			iput(inode);
			return ERR_PTR(err);
		}
	}
	return inode;
}

static int tuxio(struct file *file, char *data, unsigned len, int write)
{
	int err = 0;
	struct inode *inode = file->f_inode;
	loff_t pos = file->f_pos;
	trace("%s %u bytes at %Lu, isize = 0x%Lx", write ? "write" : "read", len, (L)pos, (L)inode->i_size);
	if (write && pos + len > MAX_FILESIZE)
		return -EFBIG;
	if (!write && pos + len > inode->i_size) {
		if (pos >= inode->i_size)
			return 0;
		len = inode->i_size - pos;
	}

	if (write)
		inode->i_mtime = inode->i_ctime = gettime();

	unsigned bbits = tux_sb(inode->i_sb)->blockbits;
	unsigned bsize = tux_sb(inode->i_sb)->blocksize;
	unsigned bmask = tux_sb(inode->i_sb)->blockmask;
	loff_t tail = len;
	while (tail) {
		unsigned from = pos & bmask;
		unsigned some = from + tail > bsize ? bsize - from : tail;
		int full = write && some == bsize;
		struct buffer_head *buffer = (full ? blockget : blockread)(mapping(inode), pos >> bbits);
		if (!buffer) {
			err = -EIO;
			break;
		}
		if (write){
			mark_buffer_dirty(buffer);
			memcpy(bufdata(buffer) + from, data, some);
		}
		else
			memcpy(data, bufdata(buffer) + from, some);
		trace_off("transfer %u bytes, block 0x%Lx, buffer %p", some, (L)bufindex(buffer), buffer);
		//hexdump(bufdata(buffer) + from, some);
		blockput(buffer);
		tail -= some;
		data += some;
		pos += some;
	}
	file->f_pos = pos;
	if (write) {
		if (inode->i_size < pos)
			inode->i_size = pos;
		mark_inode_dirty(inode);
	}
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

/*
 * Truncate partial block, otherwise, if uses expands size with
 * truncate(), it will show existent old data.
 */
static int truncate_partial_block(struct inode *inode, loff_t size)
{
	struct sb *sb = tux_sb(inode->i_sb);
	if (!(size & sb->blockmask))
		return 0;
	block_t index = size >> sb->blockbits;
	unsigned offset = size & sb->blockmask;
	struct buffer_head *buffer = blockread(mapping(inode), index);
	if (!buffer)
		return -EIO;
	memset(bufdata(buffer) + offset, 0, inode->i_sb->blocksize - offset);
	blockput_dirty(buffer);
	return 0;
}

int tuxtruncate(struct inode *inode, loff_t size)
{
	/* FIXME: expanding size is not tested */
	struct sb *sb = tux_sb(inode->i_sb);
	tuxkey_t index = (size + sb->blockmask) >> sb->blockbits;
	int is_expand;
	int err = 0;

	if (size == inode->i_size)
		goto out;
	is_expand = size > inode->i_size;

	inode->i_size = size;
	if (!is_expand) {
		truncate_partial_block(inode, size);
		truncate_inode_pages(mapping(inode), size);
		err = btree_chop(&inode->btree, index, TUXKEY_LIMIT);
	}
	inode->i_mtime = inode->i_ctime = gettime();
	mark_inode_dirty(inode);
out:
	return err;
}

struct inode *tuxopen(struct inode *dir, const char *name, int len)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_dirent(dir, name, len, &buffer);
	if (IS_ERR(entry))
		return ERR_CAST(entry);
	inum_t inum = from_be_u64(entry->inum);
	blockput(buffer);
	struct inode *inode = tux3_iget(dir->i_sb, inum);
	assert(PTR_ERR(inode) != -ENOENT);
	return inode;
}

struct inode *__tux_create_inode(struct inode *dir, inum_t goal,
				 struct tux_iattr *iattr, dev_t rdev)
{
	struct inode *inode = tux_new_inode(dir, iattr, rdev);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	int err = alloc_inum(inode, goal);
	if (err) {
		iput(inode);
		return ERR_PTR(err);
	}
	insert_inode_hash(inode);

	mark_inode_dirty(inode);

	return inode;
}

static struct inode *tux_create_inode(struct inode *dir, struct tux_iattr *iattr, dev_t rdev)
{
	return __tux_create_inode(dir, alloc_inum_goal(dir), iattr, rdev);
}

struct inode *tuxcreate(struct inode *dir, const char *name, int len, struct tux_iattr *iattr)
{
	struct buffer_head *buffer;
	tux_dirent *entry = tux_find_dirent(dir, name, len, &buffer);
	if (!IS_ERR(entry)) {
		blockput(buffer);
		return ERR_PTR(-EEXIST); // should allow create of a file that already exists!!!
	}
	if (PTR_ERR(entry) != -ENOENT)
		return ERR_CAST(entry);

	struct inode *inode = tux_create_inode(dir, iattr, 0);
	if (IS_ERR(inode))
		return inode;

	int err = tux_create_dirent(dir, name, len, tux_inode(inode)->inum, iattr->mode);
	if (err) {
		purge_inode(inode);
		iput(inode);
		return ERR_PTR(err);
	}

	return inode;
}

int tuxunlink(struct inode *dir, const char *name, int len)
{
	struct sb *sb = tux_sb(dir->i_sb);
	struct buffer_head *buffer;
	int err;
	tux_dirent *entry = tux_find_dirent(dir, name, len, &buffer);
	if (IS_ERR(entry)) {
		err = PTR_ERR(entry);
		goto error;
	}
	inum_t inum = from_be_u64(entry->inum);
	struct inode *inode = tux3_iget(sb, inum);
	assert(PTR_ERR(inode) != -ENOENT);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto error_iget;
	}
	err = tux_delete_dirent(buffer, entry);
	if (err)
		goto error_open;

	inode->i_ctime = dir->i_ctime;
	inode->i_nlink--;
	if (inode->i_nlink == 0) {
		/* FIXME: what to do if error? */
		err = tux3_mark_inode_orphan(inode);
		if (err)
			goto error_open;
	}

	/* FIXME: we shouldn't write inode for i_nlink = 0? */
	mark_inode_dirty_sync(inode);
	/* This iput() will truncate inode if i_nlink == 0 && i_count == 1 */
	iput(inode);

	return 0;

error_open:
	iput(inode);
error_iget:
	blockput(buffer);
error:
	return err;
}

int write_inode(struct inode *inode)
{
	/* Those inodes must not be marked as I_DIRTY_SYNC/DATASYNC. */
	assert(tux_inode(inode)->inum != TUX_VOLMAP_INO &&
	       tux_inode(inode)->inum != TUX_LOGMAP_INO &&
	       tux_inode(inode)->inum != TUX_INVALID_INO);
	switch (tux_inode(inode)->inum) {
	case TUX_BITMAP_INO:
	case TUX_VTABLE_INO:
	case TUX_ATABLE_INO:
		/* FIXME: assert(only btree should be changed); */
		break;
	}
	return save_inode(inode);
}
