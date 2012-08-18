#include "tux3user.h"
#include "test.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/dir.c"

static void clean_main(struct sb *sb, struct inode *dir)
{
	invalidate_buffers(dir->map);
	free_map(dir->map);
	put_super(sb);
}

/* Test basic dir operations */
static void test01(struct sb *sb, struct inode *dir)
{
	struct buffer_head *buffer;
	tux_dirent *entry;
	int err;

	test_assert(tux_dir_is_empty(dir) == 0);

	err = tux_create_dirent(dir, "hello", 5, 0x666, S_IFREG);
	test_assert(!err);
	err = tux_create_dirent(dir, "world", 5, 0x777, S_IFLNK);
	test_assert(!err);

	entry = tux_find_dirent(dir, "hello", 5, &buffer);
	test_assert(!IS_ERR(entry));
	test_assert(from_be_u64(entry->inum) == 0x666);
	test_assert(from_be_u16(entry->rec_len) >= 5 + 2);
	test_assert(entry->name_len == 5);
	test_assert(entry->type == TUX_REG);

	err = tux_delete_dirent(buffer, entry);
	test_assert(!err);
	entry = tux_find_dirent(dir, "hello", 5, &buffer);
	test_assert(IS_ERR(entry));

	entry = tux_find_dirent(dir, "world", 5, &buffer);
	test_assert(!IS_ERR(entry));
	test_assert(from_be_u64(entry->inum) == 0x777);
	test_assert(from_be_u16(entry->rec_len) >= 5 + 2);
	test_assert(entry->name_len == 5);
	test_assert(entry->type == TUX_LNK);
	blockput(buffer);

	test_assert(tux_dir_is_empty(dir) == -ENOTEMPTY);

	clean_main(sb, dir);
}

static int filldir(void *entry, const char *name, int namelen, loff_t offset,
		   u64 inum, unsigned type)
{
	static int pos;

	char orig[100];
	sprintf(orig, "file%i", pos);
	trace_on("%*s, %s", namelen, name, orig);
	test_assert(memcmp(orig, name, strlen(orig)) == 0);
	test_assert(inum == pos+99);
	test_assert(type == DT_REG);

	pos++;

	return 0;
}

/* Test readdir */
static void test02(struct sb *sb, struct inode *dir)
{
	struct file *file = &(struct file){ .f_inode = dir };
	int err;

	for (int i = 0; i < 10; i++) {
		char name[100];
		sprintf(name, "file%i", i);
		err = tux_create_dirent(dir, name, strlen(name), i+99, S_IFREG);
		test_assert(!err);
	}

	char dents[10000];
	err = tux_readdir(file, dents, filldir);
	test_assert(!err);

	clean_main(sb, dir);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };

	init_buffers(dev, 1 << 20, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	struct inode *dir = rapid_open_inode(sb, NULL, S_IFDIR);

	test_init(argv[0]);

	if (test_start("test01"))
		test01(sb, dir);
	test_end();

	if (test_start("test02"))
		test02(sb, dir);
	test_end();

	clean_main(sb, dir);
	return test_failures();
}
