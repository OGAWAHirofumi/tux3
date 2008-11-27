/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef main
#define main notmain0
#include "balloc.c"
#undef main

#define main notmain3
#include "dir.c"
#undef main
#endif

#ifndef trace
#define trace trace_on
#endif

#include "tux3.h"	/* include user/tux3.h, not user/kernel/tux3.h */
#include "kernel/xattr.c"

/* Xattr encode/decode */
#ifndef main
#define main notmain2
#include "ileaf.c"
#undef main
#endif

#ifndef main
#include <fcntl.h>

int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct dev *dev = &(struct dev){ .bits = 8, .fd = open(argv[1], O_CREAT|O_RDWR, S_IRWXU) };
	ftruncate(dev->fd, 1 << 24);
	map_t *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20);
	SB = &(struct sb){
		.version = 0, .atable = map->inode,
		.blockbits = dev->bits, 
		.blocksize = 1 << dev->bits, 
		.blockmask = (1 << dev->bits) - 1, 
		.atomref_base = 1 << 10,
		.unatom_base = 1 << 11,
		.atomgen = 1,
	};
	struct inode *inode = &(struct inode){ .i_sb = sb,
		.map = map, .i_mode = S_IFDIR | 0x666,
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00dULL, .depth = 3 } },
		.i_ctime = spectime(0xdec0debeadULL),
		.i_mtime = spectime(0xbadfaced00dULL) };
	map->inode = inode;
	sb->atable = inode;

	for (int i = 0; i < 2; i++) {
		struct buffer_head *buffer = blockget(mapping(inode), tux_sb(inode->i_sb)->atomref_base + i);
		memset(bufdata(buffer), 0, sb->blocksize);
		brelse_dirty(buffer);
	}

	if (1) {
		warn("---- test positive and negative refcount carry ----");
		use_atom(inode, 6, 1 << 15);
		use_atom(inode, 6, (1 << 15));
		use_atom(inode, 6, -(1 << 15));
		use_atom(inode, 6, -(1 << 15));
	}

	warn("---- test atom table ----");
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));

	warn("---- test inode xattr cache ----");
	int err = 0;
	err = xcache_update(inode, 0x666, "hello", 5);
	err = xcache_update(inode, 0x777, "world!", 6);
	xcache_dump(inode);
	struct xattr *xattr = xcache_lookup(inode, 0x777, &err);
	if (xattr)
		printf("atom %x => %.*s\n", xattr->atom, xattr->size, xattr->body);
	err = xcache_update(inode, 0x111, "class", 5);
	err = xcache_update(inode, 0x666, NULL, 0);
	err = xcache_update(inode, 0x222, "boooyah", 7);
	xcache_dump(inode);

	warn("---- test xattr inode table encode and decode ----");
	char attrs[1000] = { };
	char *top = encode_xattrs(inode, attrs, sizeof(attrs));
	hexdump(attrs, top - attrs);
	printf("predicted size = %x, encoded size = %Lx\n", encode_xsize(inode), (L)(top - attrs));
	inode->xcache->size = offsetof(struct xcache, xattrs);
	char *newtop = decode_attrs(inode, attrs, top - attrs);
	printf("predicted size = %x, xcache size = %x\n", decode_xsize(inode, attrs, top - attrs), inode->xcache->size);
	assert(top == newtop);
	xcache_dump(inode);
	free(inode->xcache);
	inode->xcache = NULL;
	warn("---- test high level ops ----");
	set_xattr(inode, "hello", 5, "world!", 6);
	set_xattr(inode, "foo", 3, "foobar", 6);
	set_xattr(inode, "bar", 3, "foobar", 6);
	xcache_dump(inode);
	for (int i = 0, len; i < 3; i++) {
		char *namelist[] = { "hello", "foo", "world" }, *name = namelist[i];
		if ((xattr = get_xattr(inode, name, len = strlen(name))))
			printf("found xattr %.*s => %.*s\n", len, name, xattr->size, xattr->body);
		else
			printf("xattr %.*s not found\n", len, name);
	}
	warn("---- test atom reverse map ----");
	for (int i = 0; i < 5; i++) {
		unsigned atom = i, offset;
		struct buffer_head *buffer = blockread_unatom(inode, atom, &offset);
		loff_t where = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
		brelse_dirty(buffer);
		buffer = blockread(mapping(inode), where >> sb->blockbits);
		printf("atom %.3Lx at dirent %.4Lx, ", (L)atom, (L)where);
		hexdump(bufdata(buffer) + (where & sb->blockmask), 16);
		brelse(buffer);
	}
	warn("---- test atom recovery ----");
	set_xattr(inode, "hello", 5, NULL, 0);
	show_freeatoms(sb);
	printf("got free atom %x\n", get_freeatom(inode));
	printf("got free atom %x\n", get_freeatom(inode));
	printf("got free atom %x\n", get_freeatom(inode));

	if (1) {
		dump_atoms(inode);
		show_buffers(map);
	}
	free(inode->xcache); // happy valgrind
	exit(0);
}
#endif
