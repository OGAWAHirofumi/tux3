/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"
#include "diskio.h"
#include "test.h"

#define trace trace_on

/* cleanup of main() */
static void clean_main(struct sb *sb)
{
	put_super(sb);
}

struct open_result {
	char name[PATH_MAX];
	int namelen;
	int err;
	inum_t inum;
};

static void check_files(struct sb *sb, struct open_result *results, int nr)
{
	/* Replay, and read file back */
	test_assert(load_sb(sb) == 0);
	sb->volmap = tux_new_volmap(sb);
	test_assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	test_assert(sb->logmap);

	void *replay_handle = replay_stage1(sb);
	test_assert(!IS_ERR(replay_handle));

	sb->bitmap = iget_or_create_inode(sb, TUX_BITMAP_INO);
	test_assert(!IS_ERR(sb->bitmap));
	sb->rootdir = iget(sb, TUX_ROOTDIR_INO);
	test_assert(!IS_ERR(sb->rootdir));
	sb->atable = iget(sb, TUX_ATABLE_INO);
	test_assert(!IS_ERR(sb->atable));
	sb->vtable = NULL;

	test_assert(replay_stage2(sb, replay_handle) == 0);

	for (int i = 0; i < nr; i++) {
		struct open_result *r = &results[i];
		struct inode *inode;

		inode = tuxopen(sb->rootdir, r->name, r->namelen);
		if (IS_ERR(inode))
			test_assert(PTR_ERR(inode) == r->err);
		else {
			test_assert(inode->inum == r->inum);
			iput(inode);
		}
	}
}

/* Generate all type of logs, and replay. */
static void test01(struct sb *sb)
{
#define NUM_FILES	100
#define NUM_FAIL	5
	static struct open_result results[NUM_FILES + NUM_FAIL];

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
	struct inode *inode;

	test_assert(make_tux3(sb) == 0);

	/*
	 * This should make at least:
	 * LOG_ROLLUP, LOG_BNODE_REDIRECT, LOG_FREEBLOCKS, LOG_BFREE_RELOG,
	 * LOG_BFREE_ON_ROLLUP
	 */
	test_assert(force_rollup(sb) == 0);
	test_assert(force_rollup(sb) == 0);

	/*
	 * This should make at least:
	 * LOG_DELTA, LOG_BALLOC, LOG_BNODE_ROOT, LOG_BNODE_SPLIT,
	 * LOG_BNODE_ADD, LOG_BNODE_UPDATE, LOG_LEAF_REDIRECT, LOG_BFREE
	 */
	for (int i = 0; i < NUM_FILES; i++) {
		struct open_result *r = &results[i];

		r->namelen = snprintf(r->name, sizeof(r->name), "file%03d", i);
		inode = tuxcreate(sb->rootdir, r->name, r->namelen, &iattr);
		test_assert(!IS_ERR(inode));
		r->err = 0;
		r->inum = inode->inum;
		iput(inode);

		if ((i % 10) == 0)
			test_assert(force_delta(sb) == 0);
	}
	for (int i = NUM_FILES; i < NUM_FILES + NUM_FAIL; i++) {
		struct open_result *r = &results[i];

		snprintf(r->name, sizeof(r->name), "file%03d", i);
		r->err = -ENOENT;
	}

	if (test_start("test01.1")) {
		test_assert(force_delta(sb) == 0);
		clean_main(sb);

		/* FIXME: fsck please */
		/* fsck(); */

		check_files(sb, results, NUM_FILES + NUM_FAIL);
		clean_main(sb);
	}
	test_end();

	if (test_start("test01.2")) {
		test_assert(force_rollup(sb) == 0);
		clean_main(sb);

		/* FIXME: fsck please */
		/* fsck(); */

		check_files(sb, results, NUM_FILES + NUM_FAIL);
		clean_main(sb);
	}
	test_end();

	test_assert(force_delta(sb) == 0);
	clean_main(sb);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);

	int fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(fd >= 0);
	u64 volsize = 1 << 24;
	int err = ftruncate(fd, volsize);
	assert(!err);

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 20, 1);

	struct disksuper super = INIT_DISKSB(dev->bits, volsize >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	test_init(argv[0]);

	if (test_start("test01"))
		test01(sb);
	test_end();

	clean_main(sb);
	return test_failures();
}
