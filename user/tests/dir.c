#include "tux3user.h"

void tux_dump_entries(struct buffer_head *buffer);
int tux_dir_is_empty(struct inode *dir);
int tux_create_dirent(struct inode *dir, const char *name, int len, inum_t inum, unsigned mode);
tux_dirent *tux_find_dirent(struct inode *dir, const char *name, int len, struct buffer_head **result);
int tux_delete_dirent(struct buffer_head *buffer, tux_dirent *entry);
int tux_readdir(struct file *file, void *state, filldir_t filldir);

static int filldir(void *entry, const char *name, int namelen, loff_t offset, u64 inum, unsigned type)
{
	printf("\"%.*s\"\n", namelen, name);
	return 0;
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8 };
	init_buffers(dev, 1 << 20, 0);

	struct disksuper super = INIT_DISKSB(dev->bits, 150);
	struct sb *sb = rapid_sb(dev);
	sb->super = super;
	setup_sb(sb, &super);

	struct inode *dir = rapid_open_inode(sb, NULL, S_IFDIR);
	struct buffer_head *buffer;
	printf("empty = %i\n", tux_dir_is_empty(dir));
	tux_create_dirent(dir, "hello", 5, 0x666, S_IFREG);
	tux_create_dirent(dir, "world", 5, 0x777, S_IFLNK);
	tux_dirent *entry = tux_find_dirent(dir, "hello", 5, &buffer);
	assert(!IS_ERR(entry));
	hexdump(entry, entry->name_len);
	tux_dump_entries(blockget(dir->map, 0));

	if (!tux_delete_dirent(buffer, entry))
		show_buffers(dir->map);

	printf("empty = %i\n", tux_dir_is_empty(dir));
	tux_dump_entries(blockget(dir->map, 0));
	struct file *file = &(struct file){ .f_inode = dir };
	for (int i = 0; i < 10; i++) {
		char name[100];
		sprintf(name, "file%i", i);
		tux_create_dirent(dir, name, strlen(name), 0x800 + i, S_IFREG);
	}
	tux_dump_entries(blockget(dir->map, 0));
	char dents[10000];
	tux_readdir(file, dents, filldir);
	show_buffers(dir->map);
	exit(0);
}
