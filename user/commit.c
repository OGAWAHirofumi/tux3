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

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	struct sb *sb = tux_sb(buffer->map->inode->i_sb);

	return devio(rw, sb_dev(sb), block << sb->blockbits, buffer->data, sb->blocksize);
}

int bitmap_io(struct buffer_head *buffer, int write)
{
	return (write) ? write_bitmap(buffer) : filemap_extent_io(buffer, 0);
}

int replay(struct sb *sb)
{
	block_t logchain = sb->logchain;
	unsigned logcount = from_be_u32(sb->super.logcount);

	trace("load %u logblocks", logcount);
	for (int i = logcount; i-- > 0;) {
		struct buffer_head *buffer = blockget(mapping(sb->logmap), i);
		if (!buffer)
			return -ENOMEM;
		int err = blockio(0, buffer, logchain);
		if (err) {
			blockput(buffer);
			return err;
		}
		struct logblock *log = bufdata(buffer);
		if (from_be_u16(log->magic) != 0x10ad) {
			warn("bad log magic %x", from_be_u16(log->magic));
			blockput(buffer);
			return -EINVAL;
		}
		logchain = from_be_u64(log->logchain);
		blockput(buffer);
	}

	for (sb->lognext = 0; sb->lognext < logcount;) {
		trace("log block %i", sb->lognext);
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = log->data;
		unsigned code;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_ALLOC:
			case LOG_FREE:
			{
				u64 block;
				unsigned count = *data++;
				data = decode48(data, &block);
				trace("%s bits 0x%Lx/%x", code == LOG_ALLOC ? "set" : "clear", (L)block, count);
				int err = update_bitmap(sb, block, count, code == LOG_ALLOC);
				warn(">>> bitmap err = %i", err);
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
			case LOG_DROOT:
			case LOG_IROOT:
			case LOG_REDIRECT:
			default:
				goto unknown;
			}
		}
		continue;
unknown:
		warn("unrecognized log code 0x%x, 0x%x", code, LOG_UPDATE);
		return -EINVAL;
	}
	return 0;
}

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
	INIT_LIST_HEAD(&sb->commit);
	INIT_LIST_HEAD(&sb->pinned);
	assert(!make_tux3(sb));
	sb->bitmap->map->io = bitmap_io;
	if (1) {
		sb->super = (struct disksuper){ .magic = SB_MAGIC, .volblocks = to_be_u64(sb->blockbits) };
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
