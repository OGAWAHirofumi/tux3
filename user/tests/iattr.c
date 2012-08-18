/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/iattr.c"

int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct dev *dev = &(struct dev){ .bits = 9 };

	struct disksuper super = INIT_DISKSB(dev->bits, 100);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	struct inode *inode = rapid_open_inode(sb, NULL, 0x666,
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.i_size = 0x123456789ULL,
		.i_ctime = spectime(0xdec0debeadULL),
		.i_mtime = spectime(0xbadfaced00dULL));
	inode->btree = (struct btree){
		.root = { .block = 0xcaba1f00dULL, .depth = 3 }
	};

	char attrs[1000] = { };
	printf("need %i attr bytes\n", encode_asize(abits));
	printf("decode %ti attr bytes\n", sizeof(attrs));
	decode_attrs(inode, attrs, sizeof(attrs));
	dump_attrs(inode);
	exit(0);
}
