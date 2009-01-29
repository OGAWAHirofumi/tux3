/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#define trace trace_off

#include "inode.c"

#undef trace
#define trace trace_on

void replay(struct sb *sb)
{
	//char *why = "something broke";
	// To do:
	// load commit blocks into map1
	// load log blocks into map2
	// scan for all fullfills
	// walk through block:
	//   if promise bread parent, apply
	//   if alloc update bitmap
	unsigned logblocks = sb->lognext, code;
	for (sb->lognext = 0; sb->lognext < logblocks;) {
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = sb->logpos;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_ALLOC:
			case LOG_FREE:
			{
				u64 block;
				unsigned count = *data++;
				data = decode48(data, &block);
				trace("%s bits 0x%Lx/%x", code == LOG_ALLOC ? "set" : "clear", (L)block, count);
				update_bitmap(sb, block, count, code == LOG_ALLOC);
				break;
			}
			case LOG_UPDATE:
			{
				u64 child, parent, key;
				data = decode48(data, &child);
				data = decode48(data, &parent);
				data = decode48(data, &key);
				trace("child = 0x%Lx, parent = 0x%Lx, key = 0x%Lx", (L)child, (L)parent, (L)key);
				break;
			}
			default:
				break; //goto eek;
			}
		}
	}
}

static int need_delta(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 10);
}

int write_bitmap(struct buffer_head *buffer)
{
	struct sb *sb = tux_sb(buffer->map->inode->i_sb);
	struct seg seg;
	int err = map_region(buffer->map->inode, buffer->index, 1, &seg, 1, 2);
	if (err < 0)
		return err;
	assert(err == 1);
	if (buffer->state - BUFFER_DIRTY == (sb->delta & (BUFFER_DIRTY_STATES - 1)))
		return -EAGAIN;
	trace("write bitmap %Lx", (L)buffer->index);
	if (!(err = diskwrite(sb->dev->fd, buffer->data, sb->blocksize, seg.block)))
		set_buffer_clean(buffer);
	return 0;
}

static int stage_delta(struct sb *sb)
{
	assert(sb->dev->bits >= 8 && sb->dev->fd);
	struct buffer_head *buffer, *safe;
	struct list_head *head = &mapping(sb->bitmap)->dirty;
	list_for_each_entry_safe(buffer, safe, head, link) {
		int err = write_bitmap(buffer);
		if (err != -EAGAIN)
			return err;
	}
	return 0;
}

static int commit_delta(struct sb *sb)
{
	return flush_state(BUFFER_DIRTY + ((sb->delta - 1) & (BUFFER_DIRTY_STATES - 1)));
}

void change_begin(struct sb *sb)
{
	down_read(&sb->delta_lock);
}

void change_end(struct sb *sb)
{
	if (need_delta(sb)) {
		unsigned delta = sb->delta;
		up_read(&sb->delta_lock);
		down_write(&sb->delta_lock);
		if (sb->delta == delta) {
			trace("commit delta %u", sb->delta);
			++sb->delta;
			stage_delta(sb);
			commit_delta(sb);
		}
		up_write(&sb->delta_lock);
	} else
		up_read(&sb->delta_lock);
}

int bitmap_io(struct buffer_head *buffer, int write)
{
	return (write) ? write_bitmap(buffer) : filemap_extent_io(buffer, 0);
}

int errio(struct buffer_head *buffer, int write)
{
	return -EINVAL;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	int fd;
	assert(fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRWXU));
	u64 volsize = 1 << 24;
	assert(!ftruncate(fd, volsize));
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 12 };
	init_buffers(dev, 1 << 20, 0);
	struct sb *sb = &(struct sb){
		INIT_SB(dev),
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.volblocks = volsize >> dev->bits,
	};
	sb->volmap = rapid_open_inode(sb, NULL, 0);
	sb->logmap = rapid_open_inode(sb, errio, 0);
	assert(!make_tux3(sb));
	sb->bitmap->map->io = bitmap_io;
	if (0) {
		for (int i = 0; i < 21; i++) {
			change_begin(sb);
			block_t block;
			assert(!balloc(sb, 1, &block));
			log_alloc(sb, block, 1, 1);
			change_end(sb);
		}
		log_finish(sb);
		replay(sb);
		show_buffers_state(BUFFER_DIRTY + 0);
		show_buffers_state(BUFFER_DIRTY + 1);
		show_buffers_state(BUFFER_DIRTY + 2);
		show_buffers_state(BUFFER_DIRTY + 3);
	}
	if (1) {
		for (int i = 0; i < 2; i++) {
			struct tux_iattr iattr = { .mode = S_IFREG | S_IRWXU };
			char name[100];
			snprintf(name, sizeof(name), "file%i", i);
			free_inode(tuxcreate(sb->rootdir, name, strlen(name), &iattr));
		}
		assert(!tuxsync(sb->rootdir));
		sb->super = (struct disksuper){ .magic = SB_MAGIC, .volblocks = to_be_u64(sb->blockbits) };
		assert(!save_sb(sb));
		assert(!flush_buffers(sb->volmap->map));
	}
	exit(0);
}
