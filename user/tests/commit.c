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

#define trace trace_on

int bitmap_io(struct buffer_head *buffer, int write)
{
	return (write) ? write_bitmap(buffer) : filemap_extent_io(buffer, 0);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	int fd;

	assert(fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR));
	u64 volsize = 1 << 24;
	assert(!ftruncate(fd, volsize));
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 20, 0);
	struct sb *sb = rapid_sb(dev, .volblocks = volsize >> dev->bits);
	sb->max_inodes_per_block = sb->blocksize / 64;
	sb->entries_per_node = calc_entries_per_node(sb->blocksize);

	sb->volmap = tux_new_volmap(sb);
	assert(sb->volmap);
	sb->logmap = tux_new_logmap(sb);
	assert(sb->logmap);

	assert(!make_tux3(sb));

	sb->bitmap->map->io = bitmap_io;
	if (1) {
		sb->super = (struct disksuper){ .magic = TUX3_MAGIC, .volblocks = to_be_u64(sb->volblocks) };
		for (int i = 0; i < 29; i++) {
			struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
			char name[100];
			snprintf(name, sizeof(name), "file%i", i);
			change_begin(sb);
			iput(tuxcreate(sb->rootdir, name, strlen(name), &iattr));
			change_end(sb);
		}
		assert(!save_sb(sb));
		//assert(!flush_buffers(sb->volmap->map));
		invalidate_buffers(sb->volmap->map);
		//show_buffers(sb->volmap->map);
		invalidate_buffers(mapping(sb->logmap));
		void *replay_handle = replay_stage1(sb);
		assert(replay_handle != NULL);
		replay_stage2(sb, replay_handle);

		/* free stash for valgrind */
		destroy_defer_bfree(&sb->new_decycle);
		destroy_defer_bfree(&sb->decycle);
		destroy_defer_bfree(&sb->derollup);
		destroy_defer_bfree(&sb->defree);
	}
	exit(0);
}
