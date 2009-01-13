/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "inode.c"
#include <popt.h>

void change_begin(struct sb *sb) { };
void change_end(struct sb *sb) { };

int fls(uint32_t v)
{
	uint32_t mask;
	int bit = 0;
	for (bit = 32, mask = 1 << 31; bit; mask >>= 1, bit--)
		if ((v & mask))
			break;
	return bit;
}

void usage(poptContext optCon, int exitcode, char *error, char *addl) {
	poptPrintUsage(optCon, stderr, 0);
	if (error) fprintf(stderr, "%s: %s\n", error, addl);
	exit(exitcode);
}

int main(int argc, const char *argv[])
{
	char opts[1001]; // overflow???
	poptContext popt;
	char *seekarg = NULL;
	unsigned blocksize = 0;
	struct poptOption options[] = {
		{ "seek", 's', POPT_ARG_STRING, &seekarg, 0, "seek offset", "<offset>" },
		{ "blocksize", 'b', POPT_ARG_INT, &blocksize, 0, "filesystem blocksize", "<size>" },
		POPT_AUTOHELP
		{ NULL, 0, 0, NULL, 0 }};

	popt = poptGetContext(NULL, argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, "<command> <volume> [<file>]");
	if (argc < 3)
		goto usage;
	int nopts = 0, c;
	while ((c = poptGetNextOpt(popt)) >= 0)
		if (memchr("", c, 0))
			opts[nopts++] = c;
	if (c < -1)
		goto badopt;
	/* open volume, create superblock */
	const char *command = poptGetArg(popt);
	const char *volname = poptGetArg(popt);
	fd_t fd = open(volname, O_RDWR, S_IRWXU);
	u64 volsize = 0;
	if (fdsize64(fd, &volsize))
		error("fdsize64 failed for '%s' (%s)", volname, strerror(errno));

	int blockbits = 12;
	if (blocksize) {
		blockbits = fls(blocksize) - 1;
		if (1 << blockbits != blocksize)
			error("blocksize must be a power of two");
	}

	struct dev *dev = &(struct dev){ fd, .bits = blockbits };
	init_buffers(dev, 1 << 20, 1);

	struct sb *sb = &(struct sb){
		INIT_SB(dev),
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.volblocks = volsize >> dev->bits,
		.freeblocks = volsize >> dev->bits,
	};
	sb->volmap = tux_new_volmap(sb);
	if (!sb->volmap)
		goto eek;
	init_btree(&sb->itable, sb, (struct root){}, &itable_ops);

	if (!strcmp(command, "mkfs") || !strcmp(command, "make")) {
		if (poptPeekArg(popt))
			goto usage;
		sb->super = (struct disksuper){ .magic = SB_MAGIC, .volblocks = to_be_u64(sb->blockbits) };
		printf("make tux3 filesystem on %s (0x%Lx bytes)\n", volname, (L)volsize);
		if ((errno = -make_tux3(sb)))
			goto eek;
		show_tree_range(&sb->itable, 0, -1);
		return 0;
	}
	if ((errno = -load_sb(sb)))
		goto eek;
	if (!(sb->bitmap = iget(sb, TUX_BITMAP_INO)))
		goto eek;
	if (!(sb->rootdir = iget(sb, TUX_ROOTDIR_INO)))
		goto eek;
	if (!(sb->atable = iget(sb, TUX_ATABLE_INO)))
		goto eek;
	if ((errno = -open_inode(sb->bitmap)))
		goto eek;
	if ((errno = -open_inode(sb->rootdir)))
		goto eek;
	if ((errno = -open_inode(sb->atable)))
		goto eek;
	show_tree_range(&sb->rootdir->btree, 0, -1);
	show_tree_range(&sb->bitmap->btree, 0, -1);
	char *filename = (void *)poptGetArg(popt);
	if (!filename)
		goto usage;

	if (!strcmp(command, "write")) {
		printf("---- open file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (!inode) {
			printf("---- create file ----\n");
			inode = tuxcreate(sb->rootdir, filename, strlen(filename),
					  &(struct tux_iattr){ .mode = S_IFREG | S_IRWXU });
			if (!inode) {
				errno = EEXIST;
				goto eek;
			}
		}
		tux_dump_entries(blockget(sb->rootdir->map, 0));
		printf("---- write file ----\n");
		struct file *file = &(struct file){ .f_inode = inode };
		//tuxseek(file, (1LL << 60) - 12);
#if 1
		struct stat stat;
		if ((fstat(0, &stat)) == -1)
			goto eek;
		if (S_ISCHR(stat.st_mode)) {
			printf("No text to write\n");
			return 1;
		}
#endif
		if (seekarg) {
			u64 seek = strtoull(seekarg, NULL, 0);
			printf("seek to %Li\n", (L)seek);
			tuxseek(file, seek);
		}
		char text[2 << 16];
		unsigned len;

#if 0
		memcpy(text, "hello", 5);
		len = 5;
#else
		while ((len = read(0, text, sizeof(text))))
#endif
			if ((errno = -tuxwrite(file, text, len)) > 0)
				goto eek;
		if ((errno = -tuxsync(inode)))
			goto eek;
		if ((errno = -sync_super(sb)))
			goto eek;
		//bitmap_dump(sb->bitmap, 0, sb->volblocks);
		tux_dump_entries(blockget(sb->rootdir->map, 0));
		//show_tree_range(&sb->itable, 0, -1);
	}

	if (!strcmp(command, "read")) {
		printf("---- read file ----\n");
		//show_tree_range(&sb->itable, 0, -1);
		//tux_dump_entries(blockread(sb->rootdir->map, 0));
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (!inode) {
			errno = ENOENT;
			goto eek;
		}
		struct file *file = &(struct file){ .f_inode = inode };
		char buf[100] = { };
		//tuxseek(file, (1LL << 60) - 12);
		if (seekarg) {
			u64 seek = strtoull(seekarg, NULL, 0);
			printf("seek to %Li\n", (L)seek);
			tuxseek(file, seek);
		}
		memset(buf, 0, sizeof(buf));
		int got = tuxread(file, buf, sizeof(buf));
		//printf("got %x bytes\n", got);
		if (got < 0)
			return 1;
		hexdump(buf, got);
	}

	if (!strcmp(command, "get") || !strcmp(command, "set")) {
		printf("---- read attribute ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (!inode) {
			errno = ENOENT;
			goto eek;
		}
		char *name = (void *)poptGetArg(popt);
		if (!name)
			goto usage;
		if (!strcmp(command, "get")) {
			printf("read xattr %.*s\n", (int)strlen(name), name);
			int size = get_xattr(inode, name, strlen(name), NULL, 0);
			if (size < 0) {
				errno = -size;
				goto eek;
			}
			void *data = malloc(size);
			if (!data) {
				errno = ENOMEM;
				goto eek;
			}
			size = get_xattr(inode, name, strlen(name), data, size);
			if (size < 0) {
				free(data);
				errno = -size;
				goto eek;
			}
			hexdump(data, size);
			free(data);
		}
		if (!strcmp(command, "set")) {
			char text[2 << 16];
			unsigned len;
			len = read(0, text, sizeof(text));
			printf("got %i bytes\n", len);
			if ((errno = -set_xattr(inode, "foo", 3, "foobar", 6, 0)))
				goto eek;
			tuxsync(inode);
			if ((errno = -sync_super(sb)))
				goto eek;
		}
	}

	if (!strcmp(command, "stat")) {
		printf("---- stat file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (!inode) {
			errno = ENOENT;
			goto eek;
		}
		dump_attrs(inode);
		free_inode(inode);
	}

	if (!strcmp(command, "delete")) {
		printf("---- delete file ----\n");
		struct buffer_head *buffer;
		tux_dirent *entry = tux_find_entry(sb->rootdir, filename, strlen(filename), &buffer);
		if (IS_ERR(entry)) {
			errno = -PTR_ERR(entry);
			goto eek;
		}
		inum_t inum = from_be_u64(entry->inum);
		struct inode *inode = iget(sb, inum);
		if ((errno = -open_inode(inode))) {
			free_inode(inode);
			goto eek;
		}
		errno = -tree_chop(&inode->btree, &(struct delete_info){ .key = 0 }, -1);
		free_inode(inode);
		if (errno)
			goto eek;
		if ((errno = -purge_inum(&sb->itable, inum)))
			goto eek;
		if ((errno = -tux_delete_entry(buffer, entry)))
			goto eek;
		tux_dump_entries(blockread(sb->rootdir->map, 0));
		if ((errno = -sync_super(sb)))
			goto eek;
	}

	if (!strcmp(command, "truncate")) {
		/*
		 * FIXME: error path may be wrong, we may invalidate
		 * buffers which truncated range, etc.
		 */
		printf("---- truncate file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (!inode) {
			errno = ENOENT;
			goto eek;
		}
		u64 seek = 0;
		if (seekarg)
			seek = strtoull(seekarg, NULL, 0);
		printf("---- new size %Lu ----\n", (L)seek);
		inode->i_size = seek;
		block_t index = (seek + sb->blockmask) >> sb->blockbits;
		if ((errno = -tree_chop(&inode->btree, &(struct delete_info){ .key = index }, 0)))
			goto eek;
		tuxsync(inode);
		if ((errno = -sync_super(sb)))
			goto eek;
	}

	//printf("---- show state ----\n");
	//show_buffers(sb->rootdir->map);
	//show_buffers(sb->volmap->map);
	poptFreeContext(popt);
	exit(0);
	return 0;
eek:
	fprintf(stderr, "%s!\n", strerror(errno));
	exit(1);
usage:
	poptPrintUsage(popt, stderr, 0);
	exit(1);
badopt:
	fprintf(stderr, "%s: %s\n", poptBadOption(popt, POPT_BADOPTION_NOALIAS), poptStrerror(c));
	exit(1);
}
