/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <getopt.h>
#include "tux3user.h"
#include "diskio.h"

#include "tux3_fsck.c"

static void usage(void)
{
	printf("tux3 [-s|--seek=<offset>] [-b|--blocksize=<size>] [-h|--help]\n"
	       "     <command> <volume> [<file>]\n");
	exit(1);
}

static int mkfs(int fd, const char *volname, unsigned blocksize)
{
	loff_t volsize = 0;
	if (fdsize64(fd, &volsize))
		strerror_exit(1, errno, "fdsize64 failed for '%s'", volname);
	int blockbits = 12;
	if (blocksize) {
		blockbits = ffs(blocksize) - 1;
		if (1 << blockbits != blocksize)
			error_exit("blocksize must be a power of two");
	}

	struct dev *dev = &(struct dev){ .fd = fd, .bits = blockbits };
	init_buffers(dev, 1 << 20, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, volsize >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = tux_new_volmap(sb);
	if (!sb->volmap)
		return -ENOMEM;

	sb->logmap = tux_new_logmap(sb);
	if (!sb->logmap)
		return -ENOMEM;

	tux3_msg(sb, "make tux3 filesystem on %s (0x%Lx bytes), blocksize %u",
		 volname, (s64)volsize, blocksize);
	int err = make_tux3(sb);
	if (!err) {
		show_tree_range(itable_btree(sb), 0, -1);
		put_super(sb);
		tux3_exit_mem();
	}
	return err;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "seek", required_argument, NULL, 's' },
		{ "blocksize", required_argument, NULL, 'b' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	unsigned blocksize = 0;
	char *seekarg = NULL;
	int err;

	while (1) {
		int c, optindex = 0;
		c = getopt_long(argc, argv, "s:b:h", long_options, &optindex);
		if (c == -1)
			break;
		switch (c) {
		case 's':
			seekarg = optarg;
			break;
		case 'b':
			blocksize = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			goto usage;
		}
	}

	if (argc - optind < 2)
		goto usage;

	err = tux3_init_mem();
	if (err)
		goto error;

	/* open volume, create superblock */
	const char *command = argv[optind++];
	const char *volname = argv[optind++];
	int fd = open(volname, O_RDWR);
	if (fd < 0)
		strerror_exit(1, errno, "couldn't open %s", volname);

	if (!strcmp(command, "mkfs") || !strcmp(command, "make")) {
		if (optind != argc)
			goto usage;
		err = mkfs(fd, volname, blocksize);
		if (err)
			goto error;
		return 0;
	}

	/* dev->bits is still unknown. Note, some structure can't use yet. */
	struct dev *dev = &(struct dev){ .fd = fd };
	struct sb *sb = rapid_sb(dev);
	err = load_sb(sb);
	if (err)
		goto error;

	dev->bits = sb->blockbits;
	init_buffers(dev, 1 << 20, 2);

	if (!strcmp(command, "fsck")) {
		err = fsck_main(sb);
		if (err)
			goto error;
		goto out;
	}

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto error;
	}
	show_tree_range(&tux_inode(sb->rootdir)->btree, 0, -1);
	show_tree_range(&tux_inode(sb->bitmap)->btree, 0, -1);

	err = replay_stage3(rp, 1);
	if (err)
		goto error;

	if (!strcmp(command, "delta")) {
		force_delta(sb);
		goto out;
	}
	if (!strcmp(command, "rollup")) {
		force_rollup(sb);
		goto out;
	}

	if (argc - optind < 1)
		goto usage;
	char *filename = argv[optind++];

	if (!strcmp(command, "write")) {
		printf("---- open file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode) && PTR_ERR(inode) == -ENOENT) {
			struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU, };
			printf("---- create file ----\n");
			inode = tuxcreate(sb->rootdir, filename, strlen(filename),
					  &iattr);
		}
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		printf("---- write file ----\n");
		struct file *file = &(struct file){ .f_inode = inode };

		struct stat stat;
		if ((fstat(0, &stat)) == -1)
			strerror_exit(1, errno, "fstat");
		if (seekarg) {
			loff_t seek = strtoull(seekarg, NULL, 0);
			printf("seek to %Li\n", (s64)seek);
			tuxseek(file, seek);
		}
		char text[1 << 16];
		while (1) {
			int len = read(0, text, sizeof(text));
			if (len < 0)
				strerror_exit(1, errno, "read");
			if (!len)
				break;
			len = tuxwrite(file, text, len);
			if (len < 0) {
				err = len;
				goto error;
			}
		}
		iput(inode);

		err = sync_super(sb);
		if (err)
			goto error;
		//bitmap_dump(sb->bitmap, 0, sb->volblocks);
		//tux_dump_entries(blockget(sb->rootdir->map, 0));
		//show_tree_range(&sb->itable, 0, -1);
	}

	if (!strcmp(command, "read")) {
		printf("---- read file ----\n");
		//show_tree_range(&sb->itable, 0, -1);
		//tux_dump_entries(blockread(sb->rootdir->map, 0));
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		struct file *file = &(struct file){ .f_inode = inode };
		char buf[100] = { };
		if (seekarg) {
			loff_t seek = strtoull(seekarg, NULL, 0);
			printf("seek to %Li\n", (s64)seek);
			tuxseek(file, seek);
		}
		memset(buf, 0, sizeof(buf));
		int got = tuxread(file, buf, sizeof(buf));
		//printf("got %x bytes\n", got);
		iput(inode);
		if (got < 0) {
			err = got;
			goto error;
		}
		hexdump(buf, got);
	}

	if (!strcmp(command, "get") || !strcmp(command, "set")) {
		printf("---- read attribute ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		if (argc - optind < 1)
			goto usage;
		char *name = argv[optind++];
		if (!strcmp(command, "get")) {
			printf("read xattr %.*s\n", (int)strlen(name), name);
			int size = get_xattr(inode, name, strlen(name), NULL, 0);
			if (size < 0) {
				err = size;
				goto error;
			}
			void *data = malloc(size);
			if (!data) {
				err = -ENOMEM;
				goto error;
			}
			size = get_xattr(inode, name, strlen(name), data, size);
			if (size < 0) {
				free(data);
				err = size;
				goto error;
			}
			hexdump(data, size);
			free(data);
		}
		if (!strcmp(command, "set")) {
			char text[2 << 16];
			unsigned len;
			len = read(0, text, sizeof(text));
			printf("got %i bytes\n", len);

			err = set_xattr(inode, "foo", 3, "foobar", 6, 0);
			if (err)
				goto error;

			err = sync_super(sb);
			if (err)
				goto error;
		}
		iput(inode);
	}

	if (!strcmp(command, "stat")) {
		printf("---- stat file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		dump_attrs(inode);
		iput(inode);
	}

	if (!strcmp(command, "delete")) {
		printf("---- delete file ----\n");
		err = tuxunlink(sb->rootdir, filename, strlen(filename));
		if (err)
			goto error;
		tux_dump_entries(blockread(sb->rootdir->map, 0));

		err = sync_super(sb);
		if (err)
			goto error;
	}

	if (!strcmp(command, "truncate")) {
		printf("---- truncate file ----\n");
		struct inode *inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		loff_t seek = 0;
		if (seekarg)
			seek = strtoull(seekarg, NULL, 0);
		printf("---- new size %Lu ----\n", (s64)seek);
		err = tuxtruncate(inode, seek);
		if (err)
			goto error;
		iput(inode);

		err = sync_super(sb);
		if (err)
			goto error;
	}

out:
	//printf("---- show state ----\n");
	//show_buffers(sb->rootdir->map);
	//show_buffers(sb->volmap->map);
	put_super(sb);
	tux3_exit_mem();

	return 0;

error:
	strerror_exit(1, -err, "eek!");
	exit(1);

usage:
	usage();
	exit(1);
}
