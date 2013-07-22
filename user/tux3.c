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
#include "diskio.h"

#include "tux3_fsck.c"
#include "tux3_image.c"

#define VERSION 0.0
#define STRINGIFY2(text) #text
#define STRINGIFY(text) STRINGIFY2(text)

static int open_volume(const char *volname)
{
	int fd = open(volname, O_RDWR);
	if (fd < 0)
		strerror_exit(1, errno, "could not open '%s'", volname);
	return fd;
}

static int open_sb(const char *volname, struct sb *sb)
{
	sb->dev->fd = open_volume(volname);

	int err = load_sb(sb);
	if (!err) {
		sb->dev->bits = sb->blockbits;
		init_buffers(sb->dev, 1 << 20, 2);
	}
	return err;
}

static int open_fs(const char *volname, struct sb *sb)
{
	int err = open_sb(volname, sb);
	if (err)
		return err;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp))
		return PTR_ERR(rp);
	show_tree_range(&tux_inode(sb->rootdir)->btree, 0, -1);
	show_tree_range(&tux_inode(sb->bitmap)->btree, 0, -1);

	return replay_stage3(rp, 1);
}

static int mkfs(const char *volname, struct sb *sb, unsigned blocksize)
{
	int fd = open_volume(volname);

	loff_t volsize = 0;
	if (fdsize64(fd, &volsize))
		strerror_exit(1, errno, "fdsize64 failed for '%s'", volname);

	printf("Volume size = %Lu bytes\n", (s64)volsize);

	int blockbits = ffs(blocksize) - 1;
	if (1 << blockbits != blocksize)
		error_exit("blocksize must be a power of two");

	sb->dev->fd = fd;
	sb->dev->bits = blockbits;
	init_buffers(sb->dev, 1 << 20, 2);

	sb->super = INIT_DISKSB(blockbits, volsize >> blockbits);
	setup_sb(sb, &sb->super);

	sb->volmap = tux_new_volmap(sb);
	if (!sb->volmap)
		return -ENOMEM;

	sb->logmap = tux_new_logmap(sb);
	if (!sb->logmap)
		return -ENOMEM;

	return make_tux3(sb);
}

static void usage(struct options *options, const char *progname,
		  const char *cmdname, const char *name, const char *blurb)
{
	int cols = 80, tabs[] = { 3, 40, cols < 60 ? 60 : cols };
	char lead[300], help[3000] = {};

	if (cmdname)
		snprintf(lead, sizeof(lead), "Usage: %s %s %s%s",
			 progname, cmdname, name, blurb ? : "");
	else
		snprintf(lead, sizeof(lead), "Usage: %s %s%s",
			 progname, name, blurb ? : "");

	opthelp(help, sizeof(help), options, tabs, lead, !blurb);
	printf("%s\n", help);
}

struct vars { const char *volname; unsigned blocksize; long long seek; int verbose; };

static void command_options(int *argc, const char ***args,
		struct options *options, int need, const char *progname,
		const char *cmdname, const char *blurb, struct vars *vars)
{
	unsigned space = optspace(options, *argc, *args);
	void *optv = malloc(space);
	if (!optv)
		strerror_exit(1, errno, "malloc");

	int optc = optscan(options, argc, args, optv, space);
	if (optc < 0)
		error_exit("%s!", opterror(optv));

	for (int i = 0; i < optc; i++) {
		const char *value = optvalue(optv, i);
		switch (options[optindex(optv, i)].terse[0]) {
		case 'b':
			vars->blocksize = strtoul(value, NULL, 0);
			break;
		case 's':
			vars->seek = strtoull(value, NULL, 0);
			break;
		case 'v':
			vars->verbose++;
			break;
		case '?':
			usage(options, progname, cmdname, blurb, " [OPTIONS]");
			exit(0);
		case 0:
			usage(options, progname, cmdname, blurb, NULL);
			exit(0);
		}
	}

	if (*argc != need) {
		usage(options, progname, cmdname, blurb, NULL);
		exit(1);
	}

	assert(need > 2);
	vars->volname = (*args)[2];
}

int main(int argc, char *argv[])
{
	const char *progname = optbasename(argv[0]);
	const char **args = (const char **)argv;
	const char *blurb = "<command> <volume>";

	enum {
		CMD_MKFS, CMD_FSCK, CMD_DELTA, CMD_UNIFY, CMD_IMAGE,
		CMD_READ, CMD_WRITE, CMD_GET, CMD_SET, CMD_STAT, CMD_DELETE,
		CMD_TRUNCATE, CMD_UNKNOWN,
	};

	static char *commands[] = {
		[CMD_MKFS] = "mkfs", [CMD_FSCK] = "fsck", [CMD_DELTA] = "delta",
		[CMD_UNIFY] = "unify", [CMD_IMAGE] = "image",
		[CMD_READ] = "read", [CMD_WRITE] = "write",
		[CMD_GET] = "get", [CMD_SET] = "set",
		[CMD_STAT] = "stat", [CMD_DELETE] = "delete",
		[CMD_TRUNCATE] = "truncate",
	};

	struct options options[] = {
		{ "commands", "L", 0, "List commands", },
		{ "verbose", "v", OPT_MANY, "Verbose output", },
		{ "version", "V", 0, "Show version", },
		{ "usage", "", 0, "Show usage", },
		{ "help", "?", 0, "Show help", },
		{},
	};

	unsigned space = optspace(options, argc, args);
	void *optv = malloc(space);
	if (!optv)
		strerror_exit(1, errno, "malloc");

	/* 2 == require progname and command */
	int optc = opthead(options, &argc, &args, optv, space, 2);
	if (optc < 0)
		error_exit("%s!", opterror(optv));

	int verbose = 0;

	for (int i = 0; i < optc; i++) {
		switch (options[optindex(optv, i)].terse[0]) {
		case 'L':
			for (int j = 0; j < ARRAY_SIZE(commands); j++)
				printf("%s ", commands[j]);
			printf("\n");
			exit(0);
		case 'v':
			verbose++;
			break;
		case 'V':
			printf("Tux3 tools version %s\n", STRINGIFY(VERSION));
			exit(0);
		case '?':
			usage(options, progname, NULL, blurb, " [OPTIONS]");
			exit(0);
		case 0:
			usage(options, progname, NULL, blurb, NULL);
			exit(0);
		}
	}

	/* At least, user has to specify "command" */
	if (argc < 2) {
		usage(options, progname, NULL, blurb, NULL);
		exit(1);
	}

	const char *command = args[1], *filename, *attrname;
	struct vars vars = { .blocksize = 1 << 12, .verbose = verbose };
	struct inode *inode = NULL;
	struct file *file = NULL;

	int err = tux3_init_mem();
	if (err)
		goto error;

	struct dev *dev = &(struct dev){};
	struct sb *sb = rapid_sb(dev);	/* dev->bits still zero, take care */

	struct options onlyhelp[] = {
		{ "verbose", "v", OPT_MANY, "Verbose output", },
		{ "usage", "", 0, "Show usage", },
		{ "help", "?", 0, "Show help", },
		{},
	};

	struct options onlyseek[] = {
		{ "seek", "s", OPT_HASARG | OPT_NUMBER, "Set file position", },
		{ "verbose", "v", OPT_MANY, "Verbose output", },
		{ "usage", "", 0, "Show usage", },
		{ "help", "?", 0, "Show help", },
		{},
	};

	struct options onlysize[] = {
		{ "size", "s", OPT_HASARG | OPT_NUMBER, "Specify file size", },
		{ "verbose", "v", OPT_MANY, "Verbose output", },
		{ "usage", "", 0, "Show usage", },
		{ "help", "?", 0, "Show help", },
		{},
	};

	int cmd;
	for (cmd = 0; cmd < ARRAY_SIZE(commands); cmd++) {
		if (commands[cmd] && !strcmp(command, commands[cmd]))
			break;
	}

	switch (cmd) {
	case CMD_MKFS: {
		struct options mkfs_options[] = {
			{ "blocksize", "b", OPT_HASARG | OPT_NUMBER,
			  "Set block size", },
			{ "verbose", "v", OPT_MANY, "Verbose output", },
			{ "usage", "", 0, "Show usage", },
			{ "help", "?", 0, "Show help", },
			{},
		};
		command_options(&argc, &args, mkfs_options, 3, progname, command,
				"<volume>", &vars);

		printf("Make tux3 filesystem on %s (blocksize %u)\n",
		       vars.volname, vars.blocksize);

		err = mkfs(vars.volname, sb, vars.blocksize);
		if (err)
			goto error;
		show_tree_range(itree_btree(sb), 0, -1);
	}
		break;

	case CMD_FSCK:
		command_options(&argc, &args, onlyhelp, 3, progname, command,
				"<volume>", &vars);
		err = open_sb(vars.volname, sb);
		if (err)
			goto error;
		err = fsck_main(sb);
		if (err)
			goto error;
		break;

	case CMD_IMAGE:
		command_options(&argc, &args, onlyhelp, 4, progname, command,
				"<src> <dest>", &vars);
		filename = args[3];
		err = open_sb(vars.volname, sb);
		if (err)
			goto error;
		err = image_main(sb, filename);
		if (err)
			goto error;
		break;

	case CMD_DELTA:
		command_options(&argc, &args, onlyhelp, 3, progname, command,
				"<volume>", &vars);
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		force_delta(sb);
		break;

	case CMD_UNIFY:
		command_options(&argc, &args, onlyhelp, 3, progname, command,
				"<volume>", &vars);
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		force_unify(sb);
		break;

	case CMD_WRITE:
		command_options(&argc, &args, onlyseek, 4, progname, command,
				"<volume> <filename>", &vars);
		filename = args[3];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode) && PTR_ERR(inode) == -ENOENT) {
			struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU, };
			inode = tuxcreate(sb->rootdir, filename, strlen(filename),
					  &iattr);
		}
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		file = &(struct file){ .f_inode = inode };
		struct stat stat;
		if ((fstat(0, &stat)) == -1)
			strerror_exit(1, errno, "fstat");
		if (vars.seek)
			tuxseek(file, vars.seek);
		char text[1 << 16];
		while (1) {
			ssize_t len = read(0, text, sizeof(text));
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
		//show_tree_range(&sb->itree, 0, -1);
		break;

	case CMD_READ:
		command_options(&argc, &args, onlyseek, 4, progname, command,
				"<volume> <filename>", &vars);
		filename = args[3];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		//show_tree_range(&sb->itree, 0, -1);
		//tux_dump_entries(blockread(sb->rootdir->map, 0));
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		file = &(struct file){ .f_inode = inode };
		char buf[100];
		memset(buf, 0, sizeof(buf));
		if (vars.seek)
			tuxseek(file, vars.seek);
		int got = tuxread(file, buf, sizeof(buf));
		//printf("got %x bytes\n", got);
		iput(inode);
		if (got < 0) {
			err = got;
			goto error;
		}
		hexdump(buf, got);
		break;

	case CMD_SET:
		command_options(&argc, &args, onlyhelp, 5, progname, command,
				"<volume> <filename> <attribute>", &vars);
		filename = args[3];
		attrname = args[4];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		ssize_t len;
		len = read(0, text, sizeof(text));
		if (len < 0)
			strerror_exit(1, errno, "read");
		if (verbose)
			printf("got %zd bytes\n", len);
		err = set_xattr(inode, attrname, strlen(attrname), text, len, 0);
		iput(inode);
		if (err)
			goto error;

		err = sync_super(sb);
		if (err)
			goto error;
		break;

	case CMD_GET:
		command_options(&argc, &args, onlyhelp, 5, progname, command,
				"<volume> <filename> <attribute>", &vars);
		filename = args[3];
		attrname = args[4];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		int size = get_xattr(inode, attrname, strlen(attrname), NULL, 0);
		if (size < 0) {
			err = size;
			goto error;
		}
		void *data = malloc(size);
		if (!data) {
			err = -ENOMEM;
			goto error;
		}
		size = get_xattr(inode, attrname, strlen(attrname), data, size);
		if (size < 0) {
			free(data);
			err = size;
			goto error;
		}
		hexdump(data, size);
		free(data);
		iput(inode);
		break;

	case CMD_STAT:
		command_options(&argc, &args, onlyhelp, 4, progname, command,
				"<volume> <filename>", &vars);
		filename = args[3];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		dump_attrs(inode);
		iput(inode);
		break;

	case CMD_DELETE:
		command_options(&argc, &args, onlyhelp, 4, progname, command,
				"<volume> <filename>", &vars);
		filename = args[3];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		err = tuxunlink(sb->rootdir, filename, strlen(filename));
		if (err) {
			if (err == -ENOENT)
				printf("File not found\n");
			else
				goto error;
		}
		tux_dump_entries(blockread(sb->rootdir->map, 0));

		err = sync_super(sb);
		if (err)
			goto error;
		break;

	case CMD_TRUNCATE:
		command_options(&argc, &args, onlysize, 4, progname, command,
				"<volume> <filename>", &vars);
		filename = args[3];
		err = open_fs(vars.volname, sb);
		if (err)
			goto error;
		inode = tuxopen(sb->rootdir, filename, strlen(filename));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		err = tuxtruncate(inode, vars.seek);
		iput(inode);
		if (err)
			goto error;

		err = sync_super(sb);
		if (err)
			goto error;
		break;

	default:
		error_exit("'%s' is not a command", command);
	}

	//printf("---- show state ----\n");
	//show_buffers(sb->rootdir->map);
	//show_buffers(sb->volmap->map);
	put_super(sb);
	tux3_exit_mem();
	free(argv2optv(args));	/* Free memory allocated by command_options() */
	free(optv);
	return 0;

error:
	strerror_exit(1, -err, "eek!");
}
