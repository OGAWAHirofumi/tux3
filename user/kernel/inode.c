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

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

int store_attrs(struct inode *inode, struct tux_path path[])
{
	unsigned size = encode_asize(tux_inode(inode)->present) + encode_xsize(inode);
	void *base = tree_expand(&tux_sb(inode->i_sb)->itable, tux_inode(inode)->inum, size, path);
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

int make_inode(struct inode *inode, struct tux_iattr *iattr)
{
	SB = tux_sb(inode->i_sb);
	int err = -ENOENT, levels = sb->itable.root.depth;
	struct tux_path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, tux_inode(inode)->inum, path))) {
		free_path(path);
		return err;
	}
	struct buffer_head *leafbuf = path[levels].buffer;
//	struct ileaf *leaf = to_ileaf(bufdata(leafbuf));

	trace("create inode 0x%Lx", (L)tux_inode(inode)->inum);
	assert(!tux_inode(inode)->btree.root.depth);
	inum_t inum = tux_inode(inode)->inum;
	assert(inum < next_key(path, levels));
	while (1) {
//		printf("find empty inode in [%Lx] base %Lx\n", (L)bufindex(leafbuf), (L)ibase(leaf));
		inum = find_empty_inode(&sb->itable, bufdata(leafbuf), (L)inum);
		printf("result inum is %Lx, limit is %Lx\n", (L)inum, (L)next_key(path, levels));
		if (inum < next_key(path, levels))
			break;
		int more = advance(&sb->itable, path);
		printf("no more inode space here, advance %i\n", more);
		if (!more)
			goto errout;
	}

	inode->i_mode = iattr->mode;
	inode->i_uid = iattr->uid;
	inode->i_gid = iattr->gid;
	inode->i_mtime = inode->i_ctime = inode->i_atime = iattr->ctime;
	inode->i_nlink = 1;
	tux_inode(inode)->inum = inum;
	tux_inode(inode)->btree = new_btree(sb, &dtree_ops); // error???
	tux_inode(inode)->present = CTIME_SIZE_BIT|MODE_OWNER_BIT|DATA_BTREE_BIT;
	if ((err = store_attrs(inode, path)))
		goto eek;
	release_path(path, levels + 1);
	free_path(path);
	return 0;
eek:
	release_path(path, levels + 1);
errout:
	free_path(path);
	warn("make_inode 0x%Lx failed (%d)", (L)tux_inode(inode)->inum, err);
	return err;
}

static int open_inode(struct inode *inode)
{
	SB = tux_sb(inode->i_sb);
	int err, levels = sb->itable.root.depth;
	struct tux_path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, tux_inode(inode)->inum, path))) {
		free_path(path);
		return err;
	}
	unsigned size;
	void *attrs = ileaf_lookup(&sb->itable, tux_inode(inode)->inum, bufdata(path[levels].buffer), &size);
	if (!attrs) {
		err = -ENOENT;
		goto eek;
	}
	trace("found inode 0x%Lx", (L)tux_inode(inode)->inum);
	//ileaf_dump(&sb->itable, path[levels].buffer->data);
	//hexdump(attrs, size);
	unsigned xsize = decode_xsize(inode, attrs, size);
	err = -ENOMEM;
	if (!(tux_inode(inode)->xcache = new_xcache(xsize))) // !!! only do this when we hit an xattr !!!
		goto eek;
	decode_attrs(inode, attrs, size); // error???
	dump_attrs(inode);
	if (tux_inode(inode)->xcache)
		xcache_dump(inode);
	err = 0;
eek:
	release_path(path, levels + 1);
	free_path(path);
	return err;
}

#ifdef __KERNEL__
void tux3_clear_inode(struct inode *inode)
{
	if (tux_inode(inode)->xcache)
		kfree(tux_inode(inode)->xcache);
}

struct inode *tux3_iget(struct super_block *sb, inum_t inum)
{
	struct sb *sbi = tux_sb(sb);
	struct inode *inode;
	int err;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	tux_inode(inode)->inum = inum;
	err = open_inode(inode);
	if (err) {
		iput(inode);
		return ERR_PTR(err);
	}

	inode->i_ino = inum; /* FIXME: will overflow on 32bit arch */
	inode->i_version = 1;
	inode->i_blocks = ((inode->i_size + sbi->blockmask)
			   & ~(loff_t)sbi->blockmask) >> 9;
//	inode->i_generation = 0;
//	inode->i_flags = 0;

	switch (inode->i_mode & S_IFMT) {
	default:
//		inode->i_op = &tux3_special_inode_operations;
//		init_special_inode(inode, inode->i_mode, new_decode_dev(dev));
		break;
	case S_IFREG:
//		inode->i_op = &tux_file_iops;
//		inode->i_fop = &tux_file_fops;
//		inode->i_mapping->a_ops = &tux_aops;
		break;
	case S_IFDIR:
		inode->i_op = &tux_dir_iops;
		inode->i_fop = &tux_dir_fops;
		inode->i_mapping->a_ops = &tux_dir_aops;
//		mapping_set_gfp_mask(inode->i_mapping, GFP_USER_PAGECACHE);
		mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
		break;
	case S_IFLNK:
//		inode->i_op = &tux_symlink_iops;
//		inode->i_mapping->a_ops = &tux_aops;
		break;
	}

	return inode;
}
#endif /* !__KERNEL__ */

int save_inode(struct inode *inode)
{
	trace("save inode 0x%Lx", (L)tux_inode(inode)->inum);
	SB = tux_sb(inode->i_sb);
	int err, levels = sb->itable.root.depth;
	struct tux_path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if ((err = probe(&sb->itable, tux_inode(inode)->inum, path))) {
		free_path(path);
		return err;
	}
	unsigned size;
	if (!(ileaf_lookup(&sb->itable, tux_inode(inode)->inum, bufdata(path[levels].buffer), &size)))
		return -EINVAL;
	err = store_attrs(inode, path);
	release_path(path, levels + 1);
	free_path(path);
	return err;
}

int purge_inum(BTREE, inum_t inum)
{
	int err = -ENOENT, levels = btree->sb->itable.root.depth;
	struct tux_path *path = alloc_path(levels + 1);
	if (!path)
		return -ENOMEM;

	if (!(err = probe(btree, inum, path))) {
		struct ileaf *ileaf = to_ileaf(bufdata(path[levels].buffer));
		err = ileaf_purge(btree, inum, ileaf);
		release_path(path, levels + 1);
	}
	free_path(path);
	return err;
}
