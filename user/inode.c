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

void inode_leak_check(void)
{
	int leaks = 0;

	for (int i = 0; i < HASH_SIZE; i++) {
		struct hlist_head *head = inode_hashtable + i;
		struct hlist_node *node;
		struct inode *inode;
		hlist_for_each_entry(inode, node, head, i_hash) {
			trace_on("possible leak inode inum %Lu, i_count %d",
				 tux_inode(inode)->inum,
				 atomic_read(&inode->i_count));
			leaks++;
		}
	}

	assert(leaks == 0);
}

static void insert_inode_hash(struct inode *inode)
{
	struct hlist_head *b = inode_hashtable + hash(tux_inode(inode)->inum);
	hlist_add_head(&inode->i_hash, b);
}

void remove_inode_hash(struct inode *inode)
{
	if (!hlist_unhashed(&inode->i_hash))
		hlist_del_init(&inode->i_hash);
}

static struct inode *new_inode(struct sb *sb)
{
	struct tux3_inode *tuxnode;
	struct inode *inode;

	tuxnode = malloc(sizeof(*tuxnode));
	if (!tuxnode)
		goto error;

	inode_init(tuxnode, sb, 0);
	inode = &tuxnode->vfs_inode;

	inode->map = new_map(sb->dev, NULL);
	if (!inode->map)
		goto error_map;

	inode->map->inode = inode;

	return inode;

error_map:
	free(tuxnode);
error:
	return NULL;
}

static void free_inode(struct inode *inode)
{
	struct tux3_inode *tuxnode = tux_inode(inode);

	inode->i_state &= ~I_BAD;

	free_inode_check(tuxnode);

	free_map(mapping(inode));
	free(tuxnode);
}

/* This is just to clean inode is partially initialized */
static void make_bad_inode(struct inode *inode)
{
	remove_inode_hash(inode);
	inode->i_state |= I_BAD;
}

static int is_bad_inode(struct inode *inode)
{
	return inode->i_state & I_BAD;
}

static void unlock_new_inode(struct inode *inode)
{
	inode->i_state &= ~I_NEW;
}

static void iget_failed(struct inode *inode)
{
	make_bad_inode(inode);
	unlock_new_inode(inode);
	iput(inode);
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

/* get additional reference to inode; caller must already hold one. */
void ihold(struct inode *inode)
{
	assert(!(inode->i_state & I_FREEING));
	assert(atomic_read(&inode->i_count) >= 1);
	atomic_inc(&inode->i_count);
}

static struct inode *find_inode(struct sb *sb, struct hlist_head *head,
				int (*test)(struct inode *, void *),
				void *data)
{
	struct hlist_node *node;
	struct inode *inode;

	hlist_for_each_entry(inode, node, head, i_hash) {
		if (test(inode, data)) {
			__iget(inode);
			return inode;
		}
	}
	return NULL;
}

struct inode *iget5_locked(struct sb *sb, inum_t inum,
			   int (*test)(struct inode *, void *),
			   int (*set)(struct inode *, void *), void *data)
{
	struct hlist_head *head = inode_hashtable + hash(inum);
	struct inode *inode;

	inode = find_inode(sb, head, test, data);
	if (inode)
		return inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;
	if (set(inode, data)) {
		free_inode(inode);
		return NULL;
	}

	inode->i_state = I_NEW;
	hlist_add_head(&inode->i_hash, head);

	return inode;
}

/* Truncate partial block. If partial, we have to update last block. */
static int tux3_truncate_partial_block(struct inode *inode, loff_t newsize)
{
	struct sb *sb = tux_sb(inode->i_sb);
	block_t index = newsize >> sb->blockbits;
	unsigned offset = newsize & sb->blockmask;
	struct buffer_head *buffer, *clone;

	if (!offset)
		return 0;

	buffer = blockread(mapping(inode), index);
	if (!buffer)
		return -EIO;

	clone = blockdirty(buffer, sb->delta);
	if (IS_ERR(clone)) {
		blockput(buffer);
		return PTR_ERR(clone);
	}

	memset(bufdata(clone) + offset, 0, sb->blocksize - offset);
	mark_buffer_dirty_non(clone);
	blockput(clone);

	return 0;
}

/* For now, we doesn't cache inode */
static int generic_drop_inode(struct inode *inode)
{
	return 1;
}

#include "kernel/inode.c"

static void tux_setup_inode(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);

	assert(tux_inode(inode)->inum != TUX_INVALID_INO);
	switch (inode->i_mode & S_IFMT) {
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFBLK:
	case S_IFCHR:
		inode->map->io = dev_errio;
		break;
	case S_IFREG:
		inode->map->io = tux3_filemap_overwrite_io;
		break;
	case S_IFDIR:
	case S_IFLNK:
		inode->map->io = tux3_filemap_redirect_io;
		break;
	case 0: /* internal inode */
		/* FIXME: bitmap, logmap, vtable, atable doesn't have S_IFMT */
		switch (tux_inode(inode)->inum) {
		case TUX_BITMAP_INO:
		case TUX_VTABLE_INO:
		case TUX_ATABLE_INO:
			/* set fake i_size to escape the check of block_* */
			inode->i_size = vfs_sb(sb)->s_maxbytes;
			inode->map->io = tux3_filemap_redirect_io;
			break;
		case TUX_LOGMAP_INO:
			inode->map->io = dev_errio;
			break;
		case TUX_VOLMAP_INO:
			inode->i_size = (loff_t)sb->volblocks << sb->blockbits;
			/* use default handler for map->io */;
			break;
		default:
			assert(0);
			break;
		}
		break;
	default:
		error("Unknown mode: inum %Lx, mode %07ho",
		      tux_inode(inode)->inum, inode->i_mode);
		break;
	}
}

struct inode *tux3_ilookup(struct sb *sb, inum_t inum)
{
	struct hlist_head *head = inode_hashtable + hash(inum);
	return find_inode(sb, head, tux_test, &inum);
}

/*
 * NOTE: iput() must not be called inside of change_begin/end() if
 * i_nlink == 0.  Otherwise, it will become cause of deadlock.
 */
void iput(struct inode *inode)
{
	if (inode == NULL)
		return;

	if (atomic_dec_and_test(&inode->i_count)) {
		if (!tux3_drop_inode(inode)) {
			/* Keep the inode on dirty list */
			return;
		}

		tux3_evict_inode(inode);

		remove_inode_hash(inode);
		free_inode(inode);
	}
}

int __tuxtruncate(struct inode *inode, loff_t size)
{
	return tux3_truncate(inode, size);
}

int tuxtruncate(struct inode *inode, loff_t size)
{
	struct sb *sb = tux_sb(inode->i_sb);
	int err;

	change_begin(sb);
	tux3_iattrdirty(inode);
	err = __tuxtruncate(inode, size);
	change_end(sb);

	return err;
}
