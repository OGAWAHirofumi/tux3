/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"
#include "hexdump.c"

#ifndef trace
#define trace trace_off
#endif

#include "btree-dummy.c"
#include "kernel/iattr.c"

int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct sb *sb = &(struct sb){ .version = 0, .blocksize = 1 << 9, };
	struct inode *inode = &(struct inode){
		INIT_INODE(sb, 0x666),
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
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
