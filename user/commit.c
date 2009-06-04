/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"
#include "diskio.h"

#define trace trace_off
#include "inode.c"
#undef trace
#define trace trace_on

int bitmap_io(struct buffer_head *buffer, int write)
{
	return (write) ? write_bitmap(buffer) : filemap_extent_io(buffer, 0);
}

#include "kernel/replay.c"

#ifdef ATOMIC
struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
	unsigned oldstate = buffer->state;
	assert(oldstate < BUFFER_STATES);
	newdelta &= BUFFER_DIRTY_STATES - 1;
	if (oldstate >= BUFFER_DIRTY) {
		if (oldstate - BUFFER_DIRTY == newdelta)
			return buffer;
		trace_on("---- fork buffer %p ----", buffer);
		struct buffer_head *clone = new_buffer(buffer->map);
		if (IS_ERR(clone))
			return clone;
		/* Create the cloned buffer */
		memcpy(bufdata(clone), bufdata(buffer), bufsize(buffer));
		clone->index = buffer->index;
		/* Replace the buffer by cloned buffer. */
		remove_buffer_hash(buffer);
		insert_buffer_hash(clone);
		/*
		 * FIXME: The refcount of buffer is not dropped here,
		 * the refcount may not be needed actually. Because
		 * this buffer was removed from lru list. Well, so,
		 * the backend has to free this buffer (blockput(buffer))
		 */
		buffer = clone;
	}
	set_buffer_state_list(buffer, BUFFER_DIRTY + newdelta, &buffer->map->dirty);
	__mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);

	return buffer;
}
#endif /* !ATOMIC */

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	int fd;

	assert(fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRWXU));
	u64 volsize = 1 << 24;
	assert(!ftruncate(fd, volsize));
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	init_buffers(dev, 1 << 20, 0);
	struct sb *sb = rapid_sb(dev, .volblocks = volsize >> dev->bits);
	sb->max_inodes_per_block = sb->blocksize / 64;
	sb->entries_per_node = (sb->blocksize - sizeof(struct bnode)) / sizeof(struct index_entry);
	sb->volmap = rapid_open_inode(sb, NULL, 0);
	sb->logmap = rapid_open_inode(sb, dev_errio, 0);
	assert(!make_tux3(sb));
	sb->bitmap->map->io = bitmap_io;
	if (1) {
		sb->super = (struct disksuper){ .magic = TUX3_MAGIC, .volblocks = to_be_u64(sb->volblocks) };
		for (int i = 0; i < 29; i++) {
			struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
			char name[100];
			snprintf(name, sizeof(name), "file%i", i);
			change_begin(sb);
			free_inode(tuxcreate(sb->rootdir, name, strlen(name), &iattr));
			change_end(sb);
		}
		assert(!save_sb(sb));
		//assert(!flush_buffers(sb->volmap->map));
		invalidate_buffers(sb->volmap->map);
		//show_buffers(sb->volmap->map);
		invalidate_buffers(mapping(sb->logmap));
		replay(sb);
	}
	exit(0);
}
