/*
 * Block allocation
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3user.h"
#include "test.h"

/* cleanup bitmap of main() */
static void clean_main(struct sb *sb)
{
	log_finish_cycle(sb, 1);
	tux3_clear_dirty_inode(sb->logmap);
	put_super(sb);
	tux3_exit_mem();
}

static void check(struct sb *sb, u8 intent)
{
	struct logblock *log;

	test_assert(sb->logbuf);
	log = bufdata(sb->logbuf);
	test_assert(sb->logtop >= sb->logpos);
	test_assert((sb->logpos - log->data) == log_size[intent]);
	log_finish(sb);
}

/* Tests log funcs and log_size[] */
static void test01(struct sb *sb)
{
	log_balloc(sb, 1, 2);
	check(sb, LOG_BALLOC);

	log_bfree(sb, 1, 2);
	check(sb, LOG_BFREE);

	log_bfree_on_unify(sb, 1, 2);
	check(sb, LOG_BFREE_ON_UNIFY);

	log_bfree_relog(sb, 1, 2);
	check(sb, LOG_BFREE_RELOG);

	log_leaf_redirect(sb, 1, 2);
	check(sb, LOG_LEAF_REDIRECT);

	log_leaf_free(sb, 1);
	check(sb, LOG_LEAF_FREE);

	log_bnode_redirect(sb, 1, 2);
	check(sb, LOG_BNODE_REDIRECT);

	log_bnode_root(sb, 1, 2, 3, 4, 5);
	check(sb, LOG_BNODE_ROOT);

	log_bnode_split(sb, 1, 2, 3);
	check(sb, LOG_BNODE_SPLIT);

	log_bnode_add(sb, 1, 2, 3);
	check(sb, LOG_BNODE_ADD);

	log_bnode_update(sb, 1, 2, 3);
	check(sb, LOG_BNODE_UPDATE);

	log_bnode_merge(sb, 1, 2);
	check(sb, LOG_BNODE_MERGE);

	log_bnode_del(sb, 1, 2, 3);
	check(sb, LOG_BNODE_DEL);

	log_bnode_adjust(sb, 1, 2, 3);
	check(sb, LOG_BNODE_ADJUST);

	log_bnode_free(sb, 1);
	check(sb, LOG_BNODE_FREE);

	log_freeblocks(sb, 1);
	check(sb, LOG_FREEBLOCKS);

	log_unify(sb);
	check(sb, LOG_UNIFY);

	log_delta(sb);
	check(sb, LOG_DELTA);

	clean_main(sb);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	init_buffers(dev, 1 << 20, 2);

	int err = tux3_init_mem();
	assert(!err);

	struct sb *sb = rapid_sb(dev);
	sb->super = INIT_DISKSB(dev->bits, 2048);
	assert(!setup_sb(sb, &sb->super));

	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	test_init(argv[0]);

	/* Set fake backend mark to modify backend objects. */
	tux3_start_backend(sb);

	if (test_start("test01"))
		test01(sb);
	test_end();

	tux3_end_backend();

	clean_main(sb);
	return test_failures();
}
