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
	sync_inode(inode, sb->delta);

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
	struct tux_iattr *iattr = &(struct tux_iattr){};
	struct inode *inode1, *inode2, *inode3, *inode4;
	int err;

	/* Both is deferred allocation */
	inode1 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(inode1);
	test_assert(is_defer_alloc_inum(inode1));
	inode2 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(inode2);
	test_assert(is_defer_alloc_inum(inode2));

	/* Test inum allocation */
	test_assert(inode1->inum != inode2->inum);
	/* Save first inode */
	err = sync_inode(inode1, sb->delta);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode1));

	/* Try to alloc same inum after save */
	inode3 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
	test_assert(inode3);
	test_assert(is_defer_alloc_inum(inode3));
	/* Try to alloc so far inum */
	inode4 = __tux_create_inode(sb->rootdir, 0x10000000, iattr, 0);
	test_assert(inode4);
	test_assert(is_defer_alloc_inum(inode4));
	/* Save inodes */
	err = sync_inode(inode2, sb->delta);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode2));
	err = sync_inode(inode3, sb->delta);
	test_assert(!err);
	test_assert(!is_defer_alloc_inum(inode3));

	/* Test inum allocation */
	test_assert(inode1->inum == 0x1000);
	test_assert(inode2->inum == 0x1001);
	test_assert(inode3->inum == 0x1002);
	test_assert(inode4->inum == 0x10000000);
	iput(inode1);
	iput(inode2);
	iput(inode3);

	/* Delete deferred allocation inode */
	inode4->i_nlink--;
	tux3_mark_inode_orphan(inode4);
	test_assert(is_defer_alloc_inum(inode4));
	/* will truncate inode4 */
	iput(inode4);
	test_assert(!err);

	force_rollup(sb);

	clean_main(sb);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);

	char *name = argv[1];
	int fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(!ftruncate(fd, 1 << 24));
	loff_t size = 0;
	int err = fdsize64(fd, &size);
	assert(!err);

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1 << 24, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, size >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

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

	clean_main(sb);
	return test_failures();
}
