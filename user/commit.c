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

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	struct sb *sb = tux_sb(buffer->map->inode->i_sb);
	return devio(rw, sb_dev(sb), block << sb->blockbits, buffer->data, sb->blocksize);
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
			brelse(buffer);
			return err;
		}
		struct logblock *log = bufdata(buffer);
		if (from_be_u16(log->magic) != 0x10ad) {
			warn("bad log magic %x", from_be_u16(log->magic));
			brelse(buffer);
			return -EINVAL;
		}
		logchain = from_be_u64(log->logchain);
		brelse(buffer);
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

/* Delta commit and log flush */

static int need_delta(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 10);
}

static int need_flush(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 3);
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
	if (!(err = diskwrite(sb->dev->fd, buffer->data, sb->blocksize, seg.block << sb->blockbits)))
		set_buffer_clean(buffer);
	return 0;
}

int move_deferred(struct sb *sb, u64 val)
{
	return stash_value(&sb->defree, val);
}

int retire_bfree(struct sb *sb, u64 val)
{
	return bfree(sb, val & ~(-1ULL << 48), val >> 48);
}

static int flush_log(struct sb *sb)
{
	/*
	 * Flush a snapshot of the allocation map to disk.  Physical blocks for
	 * the bitmaps and new or redirected bitmap btree nodes may be allocated
	 * during the flush.  Any bitmap blocks that are (re)dirtied by these
	 * allocations will be written out in the next flush cycle.  A redirtied
	 * bitmap block is replaced in cache by a clone, which is then modified.
	 * The original goes onto a list of forked blocks to be written out
	 * separately.
	 */

	/* further block allocations belong to the next cycle */
	sb->flush++;

	/* map dirty bitmap blocks to disk and write out */

	struct buffer_head *buffer, *safe;
	struct list_head *head = &mapping(sb->bitmap)->dirty;
	list_for_each_entry_safe(buffer, safe, head, link) {
		int err = write_bitmap(buffer);
		if (err != -EAGAIN)
			return err;
	}

	/* add pinned metadata to delta list */
	/* forked bitmap blocks from blockdirty, redirected btree nodes from cursor_redirect */
	list_splice_tail_init(&sb->pinned, &sb->commit);

	/* move deferred frees for rollup to delta deferred free list */
	unstash(sb, &sb->deflush, move_deferred);

	/* empty the log */
	sb->logbase = sb->lognext;

	return 0;
}

static int stage_delta(struct sb *sb)
{
	if (need_flush(sb)) {
		int err = flush_log(sb);
		if (err)
			return err;
	}

	assert(!tuxsync(sb->rootdir));

	/* flush forked bitmap blocks, btree node and leaf blocks */

	while (!list_empty(&sb->commit)) {
		struct buffer_head *buffer = container_of(sb->commit.next, struct buffer_head, link);
		trace(">>> flush buffer %Lx:%Lx", tux_inode(buffer_inode(buffer))->inum, (L)bufindex(buffer));
		// mapping, index set but not hashed in mapping
		buffer->map->io(buffer, 1);
		evict_buffer(buffer);
	}

	sb->delta++;

	/* allocate and write log blocks */

	if (sb->logbuf)
		log_finish(sb);
	for (unsigned index = sb->logthis; index < sb->lognext; index++) {
		block_t block;
		int err = balloc(sb, 1, &block);
		if (err)
			return err;
		struct buffer_head *buffer = blockget(mapping(sb->logmap), index);
		if (!buffer) {
			bfree(sb, block, 1);
			return -ENOMEM;
		}
		struct logblock *log = bufdata(buffer);
		log->magic = to_be_u16(0x10ad);
		log->logchain = to_be_u64(sb->logchain);
		if ((err = devio(WRITE, sb_dev(sb), block << sb->blockbits, buffer->data, sb->blocksize))) {
			brelse(buffer);
			bfree(sb, block, 1);
			return err;
		}
		defer_free(&sb->deflush, block, 1);
		brelse(buffer);
		sb->logchain = block;
	}
	sb->logthis = sb->lognext;
	return 0;
}

static int commit_delta(struct sb *sb)
{
	trace("commit %i logblocks", sb->lognext - sb->logbase);
	sb->super.logcount = to_be_u32(sb->lognext - sb->logbase);
	int err = save_sb(sb);
	if (err)
		return err;
	return unstash(sb, &sb->defree, retire_bfree);
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
			trace(">>> commit delta %u", sb->delta);
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
	INIT_LIST_HEAD(&sb->commit);
	INIT_LIST_HEAD(&sb->pinned);
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
		evict_buffers(sb->volmap->map);
		//show_buffers(sb->volmap->map);
		evict_buffers(mapping(sb->logmap));
		replay(sb);
	}
	exit(0);
}
