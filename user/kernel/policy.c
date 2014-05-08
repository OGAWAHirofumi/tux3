/*
 * Allocation policy of inum and block.
 *
 * Copyright (c) 2014 Daniel Phillips
 * Copyright (c) 2014 OGAWA Hirofumi
 */

#include "tux3.h"

//#define POLICY_LINEAR

#ifndef POLICY_LINEAR
/*
 * Want to spread out directories more at top level. How much more is
 * a wild guess. When parent is root, put each in a completely empty
 * block group. Flaw: top level mount point dirs are normally empty
 * so no other dirs will be created in that group. So relax this when
 * volume is more than XX used.
 */
static unsigned policy_mkdir_ideal(struct sb *sb, unsigned depth)
{
	unsigned groupsize = 1 << sb->groupbits;
	block_t used = sb->volblocks - sb->freeblocks;
	int age = (used >= (1 << 15)) + (used >= (1 << 18));
	unsigned ideal[3][2] = {
		{ 0, groupsize / 8 },
		{ groupsize / 16, groupsize / 2 },
		{ groupsize, groupsize },
	};

	return ideal[age][depth];
}

/*
 * Policy to choice inum for creating directory entry.
 */
inum_t policy_inum(struct inode *dir, loff_t where, struct inode *inode)
{
	enum { guess_filesize = 1 << 13, guess_dirsize = 50 * guess_filesize };
	enum { guess_dirent_size = 24, cluster = 32 };
	enum { file_factor = guess_filesize / guess_dirent_size };
	enum { dir_factor = guess_dirsize / guess_dirent_size };

	struct sb *sb = tux_sb(dir->i_sb);
	int is_dir = S_ISDIR(inode->i_mode);
	unsigned factor = is_dir ? dir_factor : file_factor;
	inum_t next = sb->nextinum; /* FIXME: racy */
	inum_t parent = tux_inode(dir)->inum;
	inum_t base = max(parent + 1, (inum_t)TUX_NORMAL_INO);
	inum_t guess = base + ((factor * where) >> sb->blockbits);
	inum_t goal = (is_dir || abs64(next - guess) > cluster) ? guess : next;

	if (is_dir) {
		enum { policy_mkdir_range = 10 };
		unsigned depth = parent != TUX_ROOTDIR_INO;
		unsigned ideal = policy_mkdir_ideal(sb, depth);
		unsigned groupbits = sb->groupbits;
		block_t group = goal >> groupbits;
		if (countmap_used(sb, group) > ideal) {
			block_t top = sb->volblocks >> groupbits;
			block_t limit = min(group + policy_mkdir_range, top);
			for (++group; group < limit; group++) {
				if (countmap_used(sb, group) <= ideal) {
					goal = group << sb->groupbits;
					break;
				}
			}
		}
	}

	return goal;
}

static block_t fold_goal(struct sb *sb, block_t goal)
{
	goal &= sb->volmask;
	if (goal >= sb->volblocks)
		goal -= (sb->volmask + 1) >> 1;
	return goal;
}

void policy_inode_init(inum_t *previous)
{
	*previous = TUX_INVALID_INO - 1;
}

/*
 * Policy to setup goal for inode for starting inode flush.
 */
void policy_inode(struct inode *inode, inum_t *previous)
{
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	/*
	 * Let inum determine block allocation goal, unless inodes are
	 * written in inum order, then use linear allocation.
	 */
	if (tuxnode->inum != ++(*previous))
		sb->nextblock = fold_goal(sb, *previous = tuxnode->inum);
}

/*
 * Policy to choice physical address for creating extents.
 */
void policy_extents(struct bufvec *bufvec)
{
	struct inode *inode = bufvec_inode(bufvec);
	struct sb *sb = tux_sb(inode->i_sb);
	block_t base = tux_inode(inode)->inum;
	unsigned blockbits = sb->blockbits, far = 1 << (21 - blockbits);
	struct buffer_head *buf = bufvec_contig_buf(bufvec);
	block_t offset = bufindex(buf);

	if (abs64(base + offset - sb->nextblock) > far)
		sb->nextblock = fold_goal(sb, base + offset);
}
#else /* POLICY_LINEAR */
inum_t policy_inum(struct inode *dir, loff_t where, struct inode *inode)
{
	return tux_sb(dir->i_sb)->nextinum;
}
void policy_inode_init(inum_t *previous)
{
}
void policy_inode(struct inode *inode, inum_t *previous)
{
}
void policy_extents(struct bufvec *bufvec)
{
}
#endif /* POLICY_LINEAR */
