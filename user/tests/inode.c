#include "tux3user.h"
#include "diskio.h"	/* for fdsize64() */

#include "../inode.c"

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	int err = 0;
	char *name = argv[1];
	int fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
	assert(!ftruncate(fd, 1 << 24));
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));

	struct dev *dev = &(struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1 << 20, 0);

	struct disksuper super = INIT_DISKSB(dev->bits, size >> dev->bits);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	trace("make tux3 filesystem on %s (0x%Lx bytes)", name, (L)size);
	if ((errno = -make_tux3(sb)))
		goto eek;
	trace("create file");
	struct inode *inode = tuxcreate(sb->rootdir, "foo", 3, &(struct tux_iattr){ .mode = S_IFREG | S_IRWXU });
	if (IS_ERR(inode))
		exit(1);
	tux_dump_entries(blockget(mapping(sb->rootdir), 0));

	trace(">>> write file");
	char buf[100] = { };
	struct file *file = &(struct file){ .f_inode = inode };
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	err = tuxwrite(file, "hello ", 6);
	err = tuxwrite(file, "world!", 6);
#if 0
	flush_buffers(mapping(sb->bitmap));
	flush_buffers(sb->volmap->map);
#endif
#if 1
	trace(">>> close file <<<");
	set_xattr(inode, "foo", 5, "hello world!", 12, 0);
	sync_inode(inode);
	iput(inode);
	trace(">>> open file");
	file = &(struct file){ .f_inode = tuxopen(sb->rootdir, "foo", 3) };
	inode = file->f_inode;
	xcache_dump(inode);
#endif
	trace(">>> read file");
	tuxseek(file, (1LL << 60) - 12);
	tuxseek(file, 4092);
	memset(buf, 0, sizeof(buf));
	int got = tuxread(file, buf, sizeof(buf));
	trace_off("got %x bytes", got);
	if (got < 0)
		exit(1);
	hexdump(buf, got);
	trace(">>> show state");
	show_buffers(mapping(file->f_inode));
	show_buffers(mapping(sb->rootdir));
	show_buffers(sb->volmap->map);
	bitmap_dump(sb->bitmap, 0, sb->volblocks);
	show_tree_range(itable_btree(sb), 0, -1);

	if (1) { /* try to allocate same inum */
		struct tux_iattr *iattr = &(struct tux_iattr){};
		struct inode *inode1, *inode2, *inode3, *inode4;
		/* both is deferred allocation */
		inode1 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
		assert(inode1);
		inode2 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
		assert(inode2);
		/* test inum allocation */
		assert(inode1->inum != inode2->inum);
		/* save first inode */
		err = sync_inode(inode1);
		assert(!err);
		/* try to alloc same inum after save */
		inode3 = __tux_create_inode(sb->rootdir, 0x1000, iattr, 0);
		assert(inode3);
		/* try to alloc so far inum */
		inode4 = __tux_create_inode(sb->rootdir, 0x10000000, iattr, 0);
		assert(inode4);
		/* save inodes */
		err = sync_inode(inode2);
		assert(!err);
		err = sync_inode(inode3);
		assert(!err);
		/* test inum allocation */
		assert(inode1->inum == 0x1000);
		assert(inode2->inum == 0x1001);
		assert(inode3->inum == 0x1002);
		assert(inode4->inum == 0x10000000);
		iput(inode1);
		iput(inode2);
		iput(inode3);
		/* delete deferred allocation inode */
		inode4->i_nlink--;
		tux_delete_inode(inode4);
	}

	destroy_defer_bfree(&sb->derollup);
	destroy_defer_bfree(&sb->defree);

	exit(0);
eek:
	return error("Eek! %s", strerror(errno));
}
