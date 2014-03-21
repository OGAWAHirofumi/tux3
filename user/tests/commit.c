/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "tux3user.h"
#include "diskio.h"
#include "test.h"

#define trace trace_on

#include "tux3_fsck.c"

/* Make snapshot of volume */
static int snapshot_fd;

static void snapshot_volume(struct sb *sb)
{
	char templete[] = "test-XXXXXX";
	char buf[4096];
	int fd;

	fd = mkstemp(templete);
	assert(fd >= 0);
	unlink(templete);

	loff_t offset = 0;
	while (1) {
		ssize_t ret, ret2;

		ret = pread(sb->dev->fd, buf, sizeof(buf), offset);
		assert(ret >= 0);
		if (!ret)
			break;

		ret2 = pwrite(fd, buf, ret, offset);
		assert(ret == ret2);

		offset += ret;
	}

	snapshot_fd = fd;
}

static void restore_volume(struct sb *sb)
{
	char buf[4096];

	assert(snapshot_fd >= 0);

	loff_t offset = 0;
	while (1) {
		ssize_t ret, ret2;

		ret = pread(snapshot_fd, buf, sizeof(buf), offset);
		assert(ret >= 0);
		if (!ret)
			break;

		ret2 = pwrite(sb->dev->fd, buf, ret, offset);
		assert(ret == ret2);

		offset += ret;
	}
}

static void clean_snapshot(void)
{
	close(snapshot_fd);
	snapshot_fd = 0;
}

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
		return 0; /* buffer is defree block */
	if (stash_walk(sb, &sb->deunify, check_defree_block) < 0)
		return 0; /* buffer is deunify block */
	/* Set fake backend mark to modify backend objects. */
	tux3_start_backend(sb);
	struct block_segment seg;
	unsigned blocks = 1;
	int segs = 0;
	int err = balloc_find_range(sb, &seg, 1, &segs, bufindex(buf), 1,
				    &blocks);
	test_assert(!err);
	tux3_end_backend();

	return blocks;	/* if blocks == 0, that block is free */
}

static void check_dirty_list(struct sb *sb, struct list_head *head)
{
	struct buffer_head *buf, *n;
	list_for_each_entry_safe(buf, n, head, link)
		test_assert(buffer_is_allocated(sb, buf));
}

/*
 * Check if freed blocks is not dirty
 * FIXME: this should move into put_super()?
 */
static void check_dirty(struct sb *sb)
{
	/* volmap only, because data buffers doesn't have block address yet */
	check_dirty_list(sb, tux3_dirty_buffers(sb->volmap, TUX3_INIT_DELTA));
	check_dirty_list(sb, &sb->unify_buffers);
}

struct open_result {
	char name[PATH_MAX];
	unsigned namelen;
	int err;
	inum_t inum;
};

static void fsck(struct sb *sb)
{
	test_assert(load_sb(sb) == 0);
	test_assert(fsck_main(sb) == 0);
	put_super(sb);
}

static struct replay *check_replay(struct sb *sb)
{
	/* Replay, and read file back */
	test_assert(load_sb(sb) == 0);

	struct replay *rp = tux3_init_fs(sb);
	assert(!IS_ERR(rp));

	return rp;
}

static void check_files(struct sb *sb, struct open_result *results, int nr)
{
	struct replay *rp = check_replay(sb);
	test_assert(replay_stage3(rp, 0) == 0);

	for (int i = 0; i < nr; i++) {
		struct open_result *r = &results[i];
		struct inode *inode;

		inode = tuxopen(sb->rootdir, r->name, r->namelen);
		if (IS_ERR(inode))
			test_assert(PTR_ERR(inode) == r->err);
		else {
			test_assert(tux_inode(inode)->inum == r->inum);
			iput(inode);
		}
	}
}

/* cleanup of sb */
static void clean_sb(struct sb *sb)
{
	/* Check if it didn't make strange dirty buffer */
	check_dirty(sb);

	put_super(sb);
}

/* cleanup of main() */
static void clean_main(struct sb *sb)
{
	clean_sb(sb);
	tux3_exit_mem();
}

/* cleanup of main() after fsck() */
static void clean_main_and_fsck(struct sb *sb)
{
	clean_sb(sb);
	fsck(sb);
	tux3_exit_mem();
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
	 * LOG_UNIFY, LOG_BNODE_REDIRECT, LOG_FREEBLOCKS, LOG_BFREE_RELOG,
	 * LOG_BFREE_ON_UNIFY
	 */
	test_assert(force_unify(sb) == 0);
	test_assert(force_unify(sb) == 0);

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
		r->inum = tux_inode(inode)->inum;

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

	snapshot_volume(sb);

	if (test_start("test01.1")) {
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, results, NUM_FILES + NUM_FAIL);
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);

	if (test_start("test01.2")) {
		test_assert(force_unify(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, results, NUM_FILES + NUM_FAIL);
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);
	test_assert(force_delta(sb) == 0);

	clean_snapshot();
	clean_main(sb);
}

/* Test to unlink file before flushing */
/*  FIXME: check if I/O is nothing for inode */
static void test02(struct sb *sb)
{
	static struct open_result r;

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

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
	clean_sb(sb);

	fsck(sb);

	check_files(sb, &r, 1);
	clean_main(sb);
}

/* Test to unlink file after flushing */
static void test03(struct sb *sb)
{
	static struct open_result r;

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

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

	snapshot_volume(sb);

	if (test_start("test03.1")) {
		/* unlink created inode */
		test_assert(tuxunlink(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);

	if (test_start("test03.2")) {
		test_assert(force_unify(sb) == 0);

		/* unlink created inode */
		test_assert(tuxunlink(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_unify(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

	clean_snapshot();
	clean_main(sb);
}

/* Create/write/unlink inode without flush */
static struct inode *make_orphan_inode(struct sb *sb, const char *name)
{
	static struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
	static char data[1024] = {};

	struct inode *inode;
	struct file *file;
	int err, size;

	inode = tuxcreate(sb->rootdir, name, strlen(name), &iattr);
	test_assert(!IS_ERR(inode));

	file = &(struct file){ .f_inode = inode };
	size = tuxwrite(file, data, sizeof(data));
	test_assert(size == sizeof(data));

	err = tuxunlink(sb->rootdir, name, strlen(name));
	assert(!err);

	return inode;
}

struct orphan_data {
	inum_t inum;
	int err;
};

static void check_orphan_inum(struct replay *rp, struct orphan_data *data,
			      int nr_data)
{
	struct sb *sb = rp->sb;

	for (int i = 0; i < nr_data; i++) {
		struct tux3_inode *tuxnode;
		struct list_head *head;
		int err = -ENOENT;
		head = &sb->orphan_add;
		list_for_each_entry(tuxnode, head, orphan_list) {
			if (data[i].inum == tuxnode->inum) {
				err = 0;
				break;
			}
		}
		head = &rp->orphan_in_otree;
		list_for_each_entry(tuxnode, head, orphan_list) {
			if (data[i].inum == tuxnode->inum) {
				err = 0;
				break;
			}
		}
		test_assert(data[i].err == err);
	}
}

/* Test for orphan inodes */
static void test04(struct sb *sb)
{
#define NR_ORPHAN	5
	struct orphan_data *data = test_alloc_shm(sizeof(*data) * NR_ORPHAN);

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

	/* Create on disk image to test lived orphan */
	pid_t pid = fork();
	assert(pid >= 0);
	if (pid == 0) {
		struct inode *inodes[NR_ORPHAN];
		LIST_HEAD(orphans);
		char name[] = "filename";

		/*
		 * inodes[0] is into sb->otree as orphan.
		 * inodes[1] is into, then delete from sb->otree
		 * inodes[2] is into sb->otree, and LOG_ORPHAN_DEL
		 * inodes[3] make LOG_ORPHAN_ADD
		 * inodes[4] make LOG_ORPHAN_ADD, and LOG_ORPHAN_DEL
		 */
		for (int i = 0; i < NR_ORPHAN; i++) {
			struct tux3_inode *tuxnode;

			inodes[i] = make_orphan_inode(sb, name);
			test_assert(!IS_ERR(inodes[i]));
			tuxnode = tux_inode(inodes[i]);

			data[i].inum = tuxnode->inum;

			switch (i) {
			case 0:
				data[i].err = 0;
				/* Add into sb->otree */
				test_assert(force_unify(sb) == 0);
				list_move(&tuxnode->orphan_list, &orphans);
				break;
			case 1:
			case 2:
				data[i].err = -ENOENT;
				/* Add into sb->otree */
				test_assert(force_unify(sb) == 0);
				iput(inodes[i]);
				if (i == 1) {
					/* Delete from sb->otree */
					test_assert(force_unify(sb) == 0);
				}
				break;
			case 3:
				data[i].err = 0;
				test_assert(force_delta(sb) == 0);
				list_move(&tuxnode->orphan_list, &orphans);
				break;
			case 4:
				data[i].err = -ENOENT;
				test_assert(force_delta(sb) == 0);
				iput(inodes[i]);
				test_assert(force_delta(sb) == 0);
				break;
			}
		}

		/* Hack: clean inodes without destroy */
		replay_iput_orphan_inodes(sb, &orphans, 0);

		clean_main(sb);
		/* Simulate crash */
		exit(1);
	}
	waitpid(pid, NULL, 0);
	clean_sb(sb);

	/* Check orphan btree and orphan logs */
	if (test_start("test04.1")) {
		/* Replay */
		struct replay *rp = check_replay(sb);

		/* Check orphan inodes */
		check_orphan_inum(rp, data, NR_ORPHAN);

		int err = replay_stage3(rp, 0);
		test_assert(!err);
		clean_sb(sb);

		fsck(sb);

		tux3_exit_mem();
	}
	test_end();

	/* Destroy orphans indoes and add orphan del log */
	if (test_start("test04.2")) {
		/* Replay */
		struct replay *rp = check_replay(sb);

		/* Destroy orphan inodes */
		int err = replay_stage3(rp, 1);
		test_assert(!err);

		/* Just add defer orphan deletion request */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		tux3_exit_mem();
	}
	test_end();

	/* test04.2 destroyed orphans */
	for (int i = 0; i < NR_ORPHAN; i++)
		data[i].err = -ENOENT;

	/* Apply orphan del logs */
	if (test_start("test04.3")) {
		/* Replay */
		struct replay *rp = check_replay(sb);

		/* Check orphan inodes */
		check_orphan_inum(rp, data, NR_ORPHAN);

		int err = replay_stage3(rp, 1);
		test_assert(!err);

		/* Remove orphan from sb->otree */
		test_assert(force_unify(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		tux3_exit_mem();
	}
	test_end();

	/* Check result */
	if (test_start("test04.4")) {
		/* Replay */
		struct replay *rp = check_replay(sb);

		/* Check orphan inodes */
		check_orphan_inum(rp, data, NR_ORPHAN);

		int err = replay_stage3(rp, 1);
		test_assert(!err);
		clean_sb(sb);

		fsck(sb);

		tux3_exit_mem();
	}
	test_end();

	tux3_exit_mem();
	test_free_shm(data, sizeof(*data) * NR_ORPHAN);
}

/* Test for mkdir/rmdir */
static void test05(struct sb *sb)
{
	static struct open_result r;

	struct tux_iattr iattr = { .mode = S_IFDIR | 0755 };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

	r.namelen = snprintf(r.name, sizeof(r.name), "dir%03d", 1);
	r.err = -ENOENT;

	/* Create dir and add some dirent without flush */
	struct inode *dir;
	dir = tuxcreate(sb->rootdir, r.name, r.namelen, &iattr);
	test_assert(!IS_ERR(dir));

	/* mkdir and rmdir subdir, this adds at least 1 buffer to dir */
	struct inode *subdir;
	const char *subname = "subdir";
	subdir = tuxcreate(dir, subname, strlen(subname), &iattr);
	test_assert(!IS_ERR(subdir));
	iput(subdir);
	test_assert(tuxrmdir(dir, subname, strlen(subname)) == 0);

	iput(dir);

	snapshot_volume(sb);

	/* rmdir after flush */
	if (test_start("test05.1")) {
		test_assert(force_delta(sb) == 0);

		/* rmdir created dir */
		test_assert(tuxrmdir(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);

	/* rmdir before flush */
	if (test_start("test05.2")) {
		/* rmdir created dir */
		test_assert(tuxrmdir(sb->rootdir, r.name, r.namelen) == 0);
		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, &r, 1);
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);
	test_assert(force_delta(sb) == 0);

	clean_snapshot();
	clean_main(sb);
}

/* Test for rename */
static void test06(struct sb *sb)
{
	static struct open_result r[] = {
		{
			.name		= "before",
			.namelen	= 6,
			.err		= -ENOENT,
		},
		{
			.name		= "after",
			.namelen	= 5,
			.err		= 0,
		},
		{
			.name		= "before2",
			.namelen	= 7,
			.err		= -ENOENT,
		},
		{
			.name		= "overwrite",
			.namelen	= 9,
			.err		= 0,
		},
	};

	struct tux_iattr iattr = { .mode = S_IFDIR | 0755 };

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

	/* Test mkdir("before"), then rename("before", "after"). */
	struct inode *subdir;
	subdir = tuxcreate(sb->rootdir, r[0].name, r[0].namelen, &iattr);
	test_assert(!IS_ERR(subdir));
	r[0].inum = tux_inode(subdir)->inum;
	iput(subdir);

	/*
	 * Test mkdir("before2") and mkdir("overwrite"), then
	 * rename("before2", "overwrite").
	 */
	subdir = tuxcreate(sb->rootdir, r[2].name, r[2].namelen, &iattr);
	test_assert(!IS_ERR(subdir));
	r[2].inum = tux_inode(subdir)->inum;
	iput(subdir);

	subdir = tuxcreate(sb->rootdir, r[3].name, r[3].namelen, &iattr);
	test_assert(!IS_ERR(subdir));
	r[3].inum = tux_inode(subdir)->inum;
	iput(subdir);
	/* Check inum is not same */
	test_assert(r[2].inum != r[3].inum);

	snapshot_volume(sb);

	/* Test rename after flush */
	if (test_start("test06.1")) {
		test_assert(force_delta(sb) == 0);

		int err;
		/* Test rename("before", "after") */
		err = tuxrename(sb->rootdir, r[0].name, r[0].namelen,
				sb->rootdir, r[1].name, r[1].namelen);
		test_assert(!err);
		/* Update inum for rename test */
		r[1].inum = r[0].inum;

		/* Test rename("before2", "overwrite") */
		err = tuxrename(sb->rootdir, r[2].name, r[2].namelen,
				sb->rootdir, r[3].name, r[3].namelen);
		test_assert(!err);
		/* Update inum for rename test */
		r[3].inum = r[2].inum;

		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, r, ARRAY_SIZE(r));
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);

	/* Test rename before flush */
	if (test_start("test06.2")) {
		int err;
		/* Test rename("before", "after") */
		err = tuxrename(sb->rootdir, r[0].name, r[0].namelen,
				sb->rootdir, r[1].name, r[1].namelen);
		test_assert(!err);
		/* Update inum for rename test */
		r[1].inum = r[0].inum;

		/* Test rename("before2", "overwrite") */
		err = tuxrename(sb->rootdir, r[2].name, r[2].namelen,
				sb->rootdir, r[3].name, r[3].namelen);
		test_assert(!err);
		/* Update inum for rename test */
		r[3].inum = r[2].inum;

		check_dirty(sb);

		/* Flush */
		test_assert(force_delta(sb) == 0);
		clean_sb(sb);

		fsck(sb);

		check_files(sb, r, ARRAY_SIZE(r));
		clean_main(sb);
	}
	test_end();

	restore_volume(sb);
	test_assert(force_delta(sb) == 0);

	clean_snapshot();
	clean_main(sb);
}

/* Test for partial alloc to flush logblocks */
static void test07(struct sb *sb)
{
	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

	tux3_start_backend(sb);
	/* Make non contiguous blocks */
	for (block_t i = 0; i < sb->volblocks; i += 2) {
		struct block_segment seg;
		unsigned blocks = 1;
		int err, segs = 0;

		err = balloc_find_range(sb, &seg, 1, &segs, i, 1, &blocks);
		test_assert(!err);
		if (blocks == 0)
			test_assert(!balloc_use(sb, &seg, 1));
	}
	/* Make 3 logblocks, at least */
	while (sb->lognext <= 3)
		log_delta(sb);
	tux3_end_backend();

	/* Flush logblocks */
	test_assert(force_delta(sb) == 0);

	clean_main(sb);
}

/* Test for replay of LOG_BNODE_FREE order */
static void test08(struct sb *sb)
{
	test_assert(make_tux3(sb) == 0);

	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
	const char name[] = "a";
	struct inode *inode;
	inode = tuxcreate(sb->rootdir, name, strlen(name), &iattr);
	test_assert(inode);
	struct file *file = &(struct file){ .f_inode = inode };
	char buf[10] = {};
	test_assert(tuxwrite(file, buf, sizeof(buf)) == sizeof(buf));
	test_assert(force_delta(sb) == 0);

	/* "freed_block" should recorded as LOG_BNODE_FREE */
	struct btree *btree = &tux_inode(inode)->btree;
	block_t freed_block = btree->root.block;
	tuxunlink(sb->rootdir, name, strlen(name));
	iput(inode);
	test_assert(force_delta(sb) == 0);

	/* Reuse "freed_block" for redirect target */
	tux3_start_backend(sb);
	struct btree *itree = itree_btree(sb);
	block_t oldblock = itree->root.block;
	log_bnode_redirect(sb, oldblock, freed_block);
	itree->root.block = freed_block;
	tux3_end_backend();

	/* Flush logblocks */
	test_assert(force_delta(sb) == 0);

	clean_main_and_fsck(sb);
}

/* Test for cross boundary allocation on countmap group and fsck */
static void test09(struct sb *sb)
{
	unsigned align = 1 << sb->groupbits;
	block_t start = align * 3;	/* pick free blocks on boundary */

	test_assert(make_tux3(sb) == 0);
	test_assert(force_unify(sb) == 0);

	tux3_start_backend(sb);
	/* Allocate cross boundary blocks */
	struct block_segment seg[10];
	unsigned blocks = 10;
	int err, segs = 0;

	err = balloc_find_range(sb, seg, ARRAY_SIZE(seg), &segs,
				start - (blocks / 2), 100, &blocks);
	test_assert(!err);
	test_assert(segs == 1);	/* supporting cross boundary allocation? */
	test_assert(!blocks);
	test_assert(!balloc_use(sb, seg, segs));
	/* Setup log records for above blocks to pass fsck */
	log_balloc(sb, seg[0].block, seg[0].count);
	log_bfree_on_unify(sb, seg[0].block, seg[0].count);
	tux3_end_backend();

	/* Flush logblocks */
	test_assert(force_delta(sb) == 0);

	clean_main_and_fsck(sb);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error_exit("usage: %s <volname>", argv[0]);

	int fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(fd >= 0);
	u64 volsize = 1 << 24;
	int err = ftruncate(fd, volsize);
	assert(!err);

	err = tux3_init_mem();
	assert(!err);

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 24, 2);

	struct sb *sb = rapid_sb(dev);
	sb->super = INIT_DISKSB(dev->bits, volsize >> dev->bits);
	assert(!setup_sb(sb, &sb->super));

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

	if (test_start("test04"))
		test04(sb);
	test_end();

	if (test_start("test05"))
		test05(sb);
	test_end();

	if (test_start("test06"))
		test06(sb);
	test_end();

	if (test_start("test07"))
		test07(sb);
	test_end();

	if (test_start("test08"))
		test08(sb);
	test_end();

	if (test_start("test09"))
		test09(sb);
	test_end();

	clean_main(sb);
	return test_failures();
}
