#include "tux3user.h"
#include "diskio.h"	/* for fdsize64() */
#include "test.h"

#ifndef trace
#define trace trace_off
#endif

#include "../inode.c"

static void clean_main(struct sb *sb)
{
	put_super(sb);
	tux3_exit_mem();
}

static int tux3_flush_inode_hack(struct inode *inode)
{
	struct sb *sb = tux_sb(inode->i_sb);
	unsigned delta;
	int err;

	/* Get delta to flush */
	change_begin_atomic(sb);
	delta = tux3_get_current_delta();
	change_end_atomic(sb);

	/* Set fake backend mark to modify backend objects. */
	tux3_start_backend(sb);
	err = tux3_flush_inode(inode, delta, 0);
	tux3_end_backend();

	return err;
}

static void test01(struct sb *sb)
{
	struct inode *inode;
	struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };

	char name[] = "foo";

	/* Test create */
	inode = tuxcreate(sb->rootdir, name, strlen(name), &iattr);
	test_assert(!IS_ERR(inode));

	struct file *file = &(struct file){ .f_inode = inode };
	int seek_pos = 4092;
	char buf[] = "hello world!";
	int size = strlen(buf);
	int low_size = size / 2;
	int high_size = size - low_size;
	int err, got;

	/* Test write data */
	tuxseek(file, seek_pos);
	got = tuxwrite(file, buf, low_size);
	test_assert(got == low_size);
	got = tuxwrite(file, buf + low_size, high_size);
	test_assert(got == high_size);
	/* Test write xattr */
	err = set_xattr(inode, name, strlen(name), buf, size, 0);
	test_assert(!err);

	iput(inode);
	tux3_flush_inode_hack(inode);

	/* Check create */
	inode = tuxopen(sb->rootdir, name, strlen(name));
	test_assert(!IS_ERR(inode));
	/* Check data */
	file = &(struct file){ .f_inode = inode, };
	tuxseek(file, seek_pos);
	char data[100];
	memset(data, 0, sizeof(data));
	got = tuxread(file, data, sizeof(data));
	test_assert(got == size);
	test_assert(!memcmp(data, buf, size));
	/* Check xattr */
	got = get_xattr(inode, name, strlen(name), data, sizeof(data));
	test_assert(got == size);
	test_assert(!memcmp(data, buf, size));
	iput(inode);

	force_delta(sb);
	clean_main(sb);
}

/* Test try to allocate same inum */
static void test02(struct sb *sb)
{
	struct tux_iattr *iattr = &(struct tux_iattr){ .mode = S_IFREG };
	struct inode *inode1, *inode2, *inode3, *inode4;
	int err;

	change_begin_atomic(sb);

	/* Both is deferred allocation */
	inode1 = tux_create_specific_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(!IS_ERR(inode1));
	test_assert(is_defer_alloc_inum(inode1));
	unlock_new_inode(inode1);
	inode2 = tux_create_specific_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(!IS_ERR(inode2));
	test_assert(is_defer_alloc_inum(inode2));
	unlock_new_inode(inode2);

	change_end_atomic(sb);

	/* Test inum allocation */
	test_assert(tux_inode(inode1)->inum != tux_inode(inode2)->inum);
	/* Save first inode */
	err = tux3_flush_inode_hack(inode1);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode1));

	change_begin_atomic(sb);

	/* Try to alloc same inum after save */
	inode3 = tux_create_specific_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(!IS_ERR(inode3));
	test_assert(is_defer_alloc_inum(inode3));
	unlock_new_inode(inode3);
	/* Try to alloc so far inum */
	inode4 = tux_create_specific_inode(sb->rootdir, 0x10000000, iattr, 0);
	test_assert(!IS_ERR(inode4));
	test_assert(is_defer_alloc_inum(inode4));
	unlock_new_inode(inode4);

	change_end_atomic(sb);

	/* Save inodes */
	err = tux3_flush_inode_hack(inode2);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode2));
	err = tux3_flush_inode_hack(inode3);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode3));

	/* Test inum allocation */
	test_assert(tux_inode(inode1)->inum == 0x1000);
	test_assert(tux_inode(inode2)->inum == 0x1001);
	test_assert(tux_inode(inode3)->inum == 0x1002);
	test_assert(tux_inode(inode4)->inum == 0x10000000);
	iput(inode1);
	iput(inode2);
	iput(inode3);

	/* Delete deferred allocation inode */
	inode4->i_nlink--;
	test_assert(is_defer_alloc_inum(inode4));
	/* will schedule inode4 deletion at next do_commit() */
	iput(inode4);
	test_assert(!err);

	force_unify(sb);

	clean_main(sb);
}

/* Create multiple directories in root */
static void test03(struct sb *sb)
{
	struct tux_iattr dir_attr = { .mode = S_IFDIR | S_IRWXU };
	struct tux_iattr reg_attr = { .mode = S_IFREG | S_IRWXU };
	struct inode *dir, *inode;
	char name[100];

	for (int d = 0; d < 3; d++) {
		snprintf(name, 100, "dir%i", d);
		trace("directory %.*s...", strlen(name), name);
		dir = tuxcreate(sb->rootdir, name, strlen(name), &dir_attr);
		test_assert(!IS_ERR(dir));

		for (int i = 0; i < 10; i++) {
			snprintf(name, 100, "foo%i", i);
			trace("create %.*s", strlen(name), name);
			inode = tuxcreate(dir, name, strlen(name), &reg_attr);
			test_assert(!IS_ERR(inode));
			iput(inode);
		}
		iput(dir);
	}

	force_delta(sb);
	clean_main(sb);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error_exit("usage: %s <volname>", argv[0]);

	char *name = argv[1];
	int fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(!ftruncate(fd, 1 << 24));
	loff_t size = 0;
	int err = fdsize64(fd, &size);
	assert(!err);

	err = tux3_init_mem();
	assert(!err);

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1 << 24, 2);

	struct sb *sb = rapid_sb(dev);
	sb->super = INIT_DISKSB(dev->bits, size >> dev->bits);
	setup_sb(sb, &sb->super);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	err = make_tux3(sb);
	assert(!err);

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
