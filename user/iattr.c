/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "hexdump.c"

#ifndef iattr_notmain_from_inode
static struct btree_ops dtree_ops;
static void init_btree(struct btree *btree, struct sb *sb, struct root root, struct btree_ops *ops)
{
	btree->sb = sb;
	btree->root = root;
	btree->ops = ops;
	btree->entries_per_leaf = 0;
}
#endif

#ifndef trace
#define trace trace_off
#endif

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/iattr.c"

#ifndef iattr_included_from_ileaf
int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct sb *sb = &(struct sb){ .version = 0, .blocksize = 1 << 9, };
	struct inode *inode = &(struct inode){ .i_sb = sb,
		.present = abits, .i_mode = 0x666, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00dULL, .depth = 3 } },
		.i_size = 0x123456789ULL,
		.i_ctime = spectime(0xdec0debeadULL),
		.i_mtime = spectime(0xbadfaced00dULL) };

	char attrs[1000] = { };
	printf("%i attributes starting from %i\n", MAX_ATTRS - MIN_ATTR, MIN_ATTR);
	printf("need %i attr bytes\n", encode_asize(abits));
	printf("decode %ti attr bytes\n", sizeof(attrs));
	decode_attrs(inode, attrs, sizeof(attrs));
	dump_attrs(inode);
	exit(0);
}
#endif
