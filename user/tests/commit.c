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

static block_t check_block;

static int check_defree_block(struct sb *sb, u64 val)
{
	block_t block = val & ~(-1ULL << 48);
	int count = val >> 48;
	if (block <= check_block && check_block < block + count)
		return -1;
	return 0;
}

/* Check if buffer is not freed blocks */
static int buffer_is_allocated(struct sb *sb, struct buffer_head *buf)
{
	check_block = bufindex(buf);
	if (stash_walk(sb, &sb->defree, check_defree_block) < 0)
		return -1; /* buffer is defree block */
	if (stash_walk(sb, &sb->derollup, check_defree_block) < 0)
		return -1; /* buffer is derollup block */

	block_t block = balloc_from_range(sb, bufindex(buf), 1, 1);
	if (block != -1) {
		bfree(sb, block, 1);
		return -1; /* buffer is freed block */
	}
	return 0;
}

static void check_dirty_list(struct sb *sb, struct list_head *head)
{
	struct buffer_head *buf, *n;
	list_for_each_entry_safe(buf, n, head, link)
		test_assert(buffer_is_allocated(sb, buf) == 0);
}

/*
 * Check if freed blocks is not dirty
 * FIXME: this should move into put_super()?
 */
static void check_dirty(struct sb *sb)
{
	/* volmap only, because data buffers doesn't have block address yet */
	check_dirty_list(sb, &mapping(sb->volmap)->dirty);
	check_dirty_list(sb, &sb->pinned);
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

/* cleanup of main() */
static void clean_main(struct sb *sb)
{
	/* Check if it didn't make strange dirty buffer */
	check_dirty(sb);

	put_super(sb);
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

		/*
		 * This should make at least:
		 * LOG_BNODE_DEL, LOG_BNODE_ADJUST
		 *
		 * FIXME: to generate LOG_BNODE_MERGE, this should use
		 * punch hole, instead of truncate(). Then, read back
		 * to check punch hole working.
		 */
		if (i == NUM_FILES - 1) {
			struct file *file = &(struct file){ .f_inode = inode };
			char data[1024] = {};
			for (int j = 0; j < 1024; j++) {
				int size = tuxwrite(file, data, sizeof(data));
				test_assert(size == sizeof(data));
				/* commit to generates many extents */
				test_assert(force_delta(sb) == 0);
			}
			test_assert(tuxtruncate(inode, 0) == 0);
		}
		iput(inode);

		if ((i % 10) == 0)
			test_assert(force_delta(sb) == 0);
	}
	for (int i = NUM_FILES; i < NUM_FILES + NUM_FAIL; i++) {
		struct open_result *r = &results[i];

		snprintf(r->name, sizeof(r->name), "file%03d", i);
		r->err = -ENOENT;
	}

	check_dirty(sb);

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

/* Test to unlink file before flushing */
/*  FIXME: check if I/O is nothing for inode */
static void test02(struct sb *sb)
{
	static struct open_result r;

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_rollup(sb) == 0);

	r.namelen = snprintf(r.name, sizeof(r.name), "file%03d", 1);
	r.err = -ENOENT;

	/* Create inode and write data without flush */
	struct inode *inode;
	inode = tuxcreate(sb->rootdir, r.name, r.namelen, &iattr);
	test_assert(!IS_ERR(inode));

	struct file *file = &(struct file){ .f_inode = inode };
	char data[1024] = {};
	for (int i = 0; i < 1024; i++) {
		int size = tuxwrite(file, data, sizeof(data));
		test_assert(size == sizeof(data));
	}
	iput(inode);
	/* unlink created inode */
	test_assert(tuxunlink(sb->rootdir, r.name, r.namelen) == 0);
	check_dirty(sb);

	/* Flush */
	test_assert(force_delta(sb) == 0);
	clean_main(sb);

	/* FIXME: fsck please */
	/* fsck(); */

	check_files(sb, &r, 1);
	clean_main(sb);
}

/* Test to unlink file after flushing */
static void test03(struct sb *sb)
{
	static struct open_result r;

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_rollup(sb) == 0);

	r.namelen = snprintf(r.name, sizeof(r.name), "file%03d", 1);
	r.err = -ENOENT;

	/* Create inode and write data without flush */
	struct inode *inode;
	inode = tuxcreate(sb->rootdir, r.name, r.namelen, &iattr);
	test_assert(!IS_ERR(inode));

	struct file *file = &(struct file){ .f_inode = inode };
	char data[1024] = {};
	for (int i = 0; i < 1024; i++) {
		int size = tuxwrite(file, data, sizeof(data));
		test_assert(size == sizeof(data));
	}
	iput(inode);
	test_assert(force_delta(sb) == 0);

	if (test_start("test03.1")) {
		/* unlink created inode */
		test_assert(tuxunlink(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_main(sb);

		/* FIXME: fsck please, check leak */
		/* fsck(); */

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

	if (test_start("test03.2")) {
		test_assert(force_rollup(sb) == 0);

		/* unlink created inode */
		test_assert(tuxunlink(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_rollup(sb) == 0);
		clean_main(sb);

		/* FIXME: fsck please, check leak */
		/* fsck(); */

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

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

	if (test_start("test02"))
		test02(sb);
	test_end();

	if (test_start("test03"))
		test03(sb);
	test_end();

	clean_main(sb);
	return test_failures();
}
