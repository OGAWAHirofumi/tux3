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
#include "test.h"

#ifndef trace
#define trace trace_off
#endif

#include "kernel/xattr.c"
#include "kernel/iattr.c"

static void clean_main(struct sb *sb)
{
	put_super(sb);
}

struct xcache_data {
	char buf[32];
	int len;
	atom_t atom;
};

static void __check_xcache(struct inode *inode, struct xcache_data *data,
			   int nr_data)
{
	for (int i = 0; i < nr_data; i++) {
		struct xattr *xattr;
		xattr = xcache_lookup(tux_inode(inode)->xcache, data[i].atom);
		if (data[i].len == -1)
			test_assert(IS_ERR(xattr));
		else {
			test_assert(!IS_ERR(xattr));
			test_assert(xattr->atom == data[i].atom);
			test_assert(xattr->size == data[i].len);
			test_assert(!memcmp(xattr->body, data[i].buf,
					    xattr->size));
		}
	}
}
#define check_xcache(i, d)	__check_xcache(i, d, ARRAY_SIZE(d))

/* Test basic low level functions */
static void test01(struct sb *sb)
{
	char attrs[1000] = { };
	struct xattr *xattr;
	int err;

	/* Test positive and negative refcount carry */
	atom_t atom;
	err = make_atom(sb->atable, "foo", 3, &atom);
	test_assert(!err);
	err = atomref(sb->atable, atom, 1 << 15);
	test_assert(!err);
	err = atomref(sb->atable, atom, 1 << 15);
	test_assert(!err);
	err = atomref(sb->atable, atom, -(1 << 15));
	test_assert(!err);
	err = atomref(sb->atable, atom, -(1 << 15));
	test_assert(!err);

	atom_t atom1, atom2, atom3;
	/* Test atom table */
	err = make_atom(sb->atable, "foo", 3, &atom1);
	test_assert(!err);
	err = make_atom(sb->atable, "foo", 3, &atom2);
	test_assert(!err);
	test_assert(atom1 == atom2);

	err = make_atom(sb->atable, "bar", 3, &atom1);
	test_assert(!err);
	err = make_atom(sb->atable, "foo", 3, &atom2);
	test_assert(!err);
	test_assert(atom1 != atom2);
	err = make_atom(sb->atable, "bar", 3, &atom3);
	test_assert(!err);
	test_assert(atom1 == atom3);

	struct inode *inode;
	struct tux_iattr iattr = { .mode = S_IFREG, };
	inode = tuxcreate(sb->rootdir, "foo", 3, &iattr);
	test_assert(inode);

	struct xcache_data data[] = {
		{ .buf = "hello ", .len = strlen("hello "), .atom = 0x666, },
		{ .buf = "world!", .len = strlen("world!"), .atom = 0x777, },
		{ .buf = "class!", .len = strlen("class!"), .atom = 0x111, },
		{ .buf = "booyah", .len = strlen("booyah"), .atom = 0x222, },
	};

	/* Test inode xcache */

	/* Create xcache */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		err = xcache_update(inode, data[i].atom, data[i].buf,
				    data[i].len, 0);
		test_assert(!err);
	}
	check_xcache(inode, data);

	/* Remove xcache */
	data[0].len = -1;
	xattr = xcache_lookup(inode->xcache, data[0].atom);
	test_assert(xattr);
	int removed = remove_old(inode->xcache, xattr);
	test_assert(removed);
	check_xcache(inode, data);

	/* Empty xcache */
	data[1].len = 0;
	err = xcache_update(inode, data[1].atom, "", data[1].len, 0);
	test_assert(!err);
	check_xcache(inode, data);

	/* Test xattr inode table encode */
	int xsize1 = encode_xsize(inode);
	test_assert(xsize1);
	char *top1 = encode_xattrs(inode, attrs, sizeof(attrs));
	test_assert(top1);
	test_assert(top1 - attrs == xsize1);

	/* Remove all xcache by hand */
	inode->xcache->size = 0;

	/* Test xattr inode table decode */
	char *top2 = decode_attrs(inode, attrs, xsize1);
	test_assert(top2);
	test_assert(top2 - attrs == xsize1);
	test_assert(top2 == top1);

	check_xcache(inode, data);

	/* Free xcache by hand */
	free_xcache(inode);

	iput(inode);

	test_assert(force_delta(sb) == 0);
	clean_main(sb);
}

struct xattr_data {
	char name[32];
	int len;
	char buf[32];
	int size;
};

static void __check_xattr(struct inode *inode, struct xattr_data *data,
			  int nr_data)
{
	for (int i = 0; i < nr_data; i++) {
		char buf[32];
		int ret;
		ret = get_xattr(inode, data[i].name, data[i].len,
				buf, sizeof(buf));
		if (data[i].len == -1)
			test_assert(ret == -ENOATTR);
		else {
			test_assert(ret == data[i].size);
			test_assert(!memcmp(buf, data[i].buf, ret));
		}
	}
}
#define check_xattr(i, d)	__check_xattr(i, d, ARRAY_SIZE(d));

static void __check_listxattr(struct inode *inode, char *buf, int len,
			      struct xattr_data *data, int nr_data)
{
	char *p = buf, *end = p + len;
	int x_count = 0, d_count = 0, n_count = 0;

	/* count not-found-entry */
	for (int i = 0; i < nr_data; i++) {
		if (data[i].len == -1)
			n_count++;
	}
	/* count matched entry */
	while (p < end) {
		for (int i = 0; i < nr_data; i++) {
			if (data[i].len == -1)
				continue;
			if (strcmp(data[i].name, p)) {
				d_count++;
				break;
			}
		}
		x_count++;
		p += strlen(p) + 1;
	}
	test_assert(x_count == d_count);
	test_assert(d_count + n_count == nr_data);
}
#define check_listxattr(i, b, l, d)		\
	__check_listxattr(i, b, l, d, ARRAY_SIZE(d))

/* Test basic interfaces */
static void test02(struct sb *sb)
{
	char attrs[1000] = { };
	int err;

	struct inode *inode;
	struct tux_iattr iattr = { .mode = S_IFREG, };
	inode = tuxcreate(sb->rootdir, "foo", 3, &iattr);
	test_assert(inode);

	struct xattr_data data[] = {
		{
			.name = "hello ", .len = strlen("hello "),
			.buf = "world!", .size = strlen("world!"),
		},
		{
			.name = "empty", .len = strlen("empty"),
			.buf = "zot", .size = strlen("zot"),
		},
		{
			.name = "foo", .len = strlen("foo"),
			.buf = "foobar", .size = strlen("foobar"),
		},
		{
			.name = "world!", .len = -1,
			.buf = "", .size = -1,
		},
	};

	/* Test create xattr */
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		if (data[i].len == -1)
			continue;
		err = set_xattr(inode, data[i].name, data[i].len,
				data[i].buf, data[i].size, 0);
		test_assert(!err);
	}
	check_xattr(inode, data);

	/* Test list xattr length */
	int checklen = list_xattr(inode, NULL, 0);
	/* Test -ERANGE */
	err = list_xattr(inode, attrs, checklen - 1);
	test_assert(err == -ERANGE);

	/* Test list xattr */
	int len = list_xattr(inode, attrs, sizeof(attrs));
	test_assert(len == checklen);
	check_listxattr(inode, attrs, len, data);

	/* Delete xattr */
	err = del_xattr(inode, data[0].name, data[0].len);
	test_assert(!err);
	data[0].len = -1;

	check_xattr(inode, data);
	len = list_xattr(inode, attrs, sizeof(attrs));
	test_assert(len);
	check_listxattr(inode, attrs, len, data);

	iput(inode);

	test_assert(force_delta(sb) == 0);
	clean_main(sb);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		error("usage: %s <volname>", argv[0]);
		exit(1);
	}

	size_t volsize = 1 << 24;
	int fd, err;

	fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(!ftruncate(fd, volsize));

	struct dev *dev = &(struct dev){ .bits = 8, .fd = fd, };
	init_buffers(dev, volsize, 2);

	struct disksuper super = INIT_DISKSB(dev->bits, volsize >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->atomref_base = 1 << 10;
	sb->unatom_base = 1 << 11;

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
