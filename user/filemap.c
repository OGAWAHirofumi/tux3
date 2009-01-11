#include "tux3.h"
#include "diskio.h"

#ifndef trace
#define trace trace_on
#endif

#define main notmain
#include "dir.c"
#undef main

#include "kernel/xattr.c"
#include "kernel/dleaf.c"
#include "kernel/btree.c"
#include "kernel/iattr.c"
#include "kernel/ileaf.c"
#include "kernel/balloc.c"
#include "kernel/filemap.c"

/*
 * Extrapolate from single buffer flush or blockread to opportunistic exent IO
 *
 * For write, try to include adjoining buffers above and below:
 *  - stop at first uncached or clean buffer in either direction
 *
 * For read (essentially readahead):
 *  - stop at first present buffer
 *  - stop at end of file
 *
 * For both, stop when extent is "big enough", whatever that means.
 */
void guess_region(struct buffer_head *buffer, block_t *start, unsigned *count, int write)
{
	struct inode *inode = buffer_inode(buffer);
	block_t ends[2] = { bufindex(buffer), bufindex(buffer) };
	for (int up = !write; up < 2; up++) {
		while (ends[1] - ends[0] + 1 < MAX_EXTENT) {
			block_t next = ends[up] + (up ? 1 : -1);
			struct buffer_head *nextbuf = peekblk(buffer->map, next);
			if (!nextbuf) {
				if (write)
					break;
				if (next > inode->i_size >> tux_sb(inode->i_sb)->blockbits)
					break;
			} else {
				unsigned stop = write ? !buffer_dirty(nextbuf) : buffer_empty(nextbuf);
				brelse(nextbuf);
				if (stop)
					break;
			}
			ends[up] = next; /* what happens to the beer you send */
		}
	}
	*start = ends[0];
	*count = ends[1] + 1 - ends[0];
}

int filemap_extent_io(struct buffer_head *buffer, int write)
{
	struct inode *inode = buffer_inode(buffer);
	struct sb *sb = tux_sb(inode->i_sb);
	trace("%s inode 0x%Lx block 0x%Lx", write ? "write" : "read", (L)tux_inode(inode)->inum, (L)bufindex(buffer));
	if (bufindex(buffer) & (-1LL << MAX_BLOCKS_BITS))
		return -EIO;
	struct dev *dev = sb->dev;
	assert(dev->bits >= 8 && dev->fd);
	if (write && buffer_empty(buffer))
		warn("egad, writing an invalid buffer");
	if (!write && buffer_dirty(buffer))
		warn("egad, reading a dirty buffer");

	block_t start;
	unsigned count;
	guess_region(buffer, &start, &count, write);
	printf("---- extent 0x%Lx/%x ----\n", (L)start, count);

	struct seg map[10];

	int segs = map_region(inode, start, count, map, ARRAY_SIZE(map), write);
	if (segs < 0)
		return segs;

	if (!segs) {
		if (!write) {
			trace("unmapped block %Lx", (L)bufindex(buffer));
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_uptodate(buffer);
			return 0;
		}
		return -EIO;
	}

	int err = 0;
	for (int i = 0, index = start; !err && i < segs; i++) {
		int count = map[i].count, hole = map[i].state == SEG_HOLE;
		trace_on("extent 0x%Lx/%x => %Lx", (L)index, count, (L)map[i].block);
		for (int j = 0; !err && j < count; j++) {
			block_t block = map[i].block + j;
			buffer = blockget(mapping(inode), index + j);
			trace_on("block 0x%Lx => %Lx", (L)bufindex(buffer), (L)block);
			if (write) {
				err = diskwrite(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			} else {
				if (hole)
					memset(bufdata(buffer), 0, sb->blocksize);
				else
					err = diskread(dev->fd, bufdata(buffer), sb->blocksize, block << dev->bits);
			}
			brelse(set_buffer_uptodate(buffer)); // leave empty if error ???
		}
		index += count;
	}
	return err;
}

struct map_ops filemap_ops = { .blockio = filemap_extent_io };

#ifndef filemap_included
void change_begin(struct sb *sb) { };
void change_end(struct sb *sb) { };

static void check_created_seg(struct seg *seg)
{
	assert(seg->block > 0);
	assert(seg->count > 0);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		error("usage: %s <volname>", argv[0]);
	char *name = argv[1];
	fd_t fd = open(name, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	ftruncate(fd, 1 << 24);
	u64 size = 0;
	if (fdsize64(fd, &size))
		error("fdsize64 failed for '%s' (%s)", name, strerror(errno));
	struct dev *dev = &(struct dev){ .fd = fd, .bits = 8 };
	struct sb *sb = &(struct sb){
		RAPID_INIT_SB(dev),
		.max_inodes_per_block = 64,
		.entries_per_node = 20,
		.volblocks = size >> dev->bits,
	};
	sb->volmap = rapid_new_inode(sb, NULL, 0);
	sb->bitmap = rapid_new_inode(sb, &filemap_ops, 0);
	init_buffers(dev, 1 << 20, 0);
	struct inode *inode = rapid_new_inode(sb, &filemap_ops, 0);
	assert(!new_btree(&inode->btree, sb, &dtree_ops));

	block_t nextalloc = sb->nextalloc;
	struct seg map[64];
	int segs;

	if (1) {
		for (int i = 0; i < 10; i++)
			segs = map_region(inode, 2*i, 1, map, 2, 1);
		show_segs(map, segs);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* create seg entirely inside existing */
		segs = map_region(inode, 2, 5, map, 10, 1); show_segs(map, segs);
		segs = map_region(inode, 4, 1, map, 10, 1); show_segs(map, segs);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) { /* seek[0] and seek[1] are same position */
		segs = map_region(inode, 0x2, 0x1, map, 10, 1);
		segs = map_region(inode, 0x6, 0x1, map, 10, 1);
		segs = map_region(inode, 0x4, 0x1, map, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}
	if (1) { /* another seek[0] and seek[1] are same position */
		segs = map_region(inode, 0x1100000, 0x40, map, 10, 1);
		segs = map_region(inode, 0x800000, 0x40, map, 10, 1);
		segs = map_region(inode, 0x800040, 0x40, map, 10, 1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		sb->nextalloc = nextalloc;
	}

	if (1) {
		struct seg seg;
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 0, j = 0; i < 30; i++, j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
		}
		show_tree_range(&inode->btree, 0, -1);
		/* tree_chop and dleaf_chop test */
		int index = 31*2;
		while (index--) {
			struct delete_info delinfo = { .key = index, };
			segs = tree_chop(&inode->btree, &delinfo, 0);
			assert(!segs);
			for (int i = 0, j = 0; i < 30; i++, j++) {
				if (index <= i*2)
					break;
				map_region(inode, i*2, 1, &seg, 1, 0);
				assert(map[j].block == seg.block);
				assert(map[j].count == seg.count);
			}
		}
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 10, j = 0; i--; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 10, j = 0; i--; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
		}
		show_tree_range(&inode->btree, 0, -1);
		/* 0/2: 0 => 3/1; 2 => 2/1; */
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}
	if (1) {
		struct seg seg;
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 1);
			assert(segs == 1);
			check_created_seg(&seg);
			map[j].block = seg.block;
			map[j].count = seg.count;
		}
		for (int i = 30, j = 0; i-- > 28; j++) {
			segs = map_region(inode, 2*i, 1, &seg, 1, 0);
			assert(segs == 1);
			check_created_seg(&seg);
			assert(map[j].block == seg.block);
			assert(map[j].count == seg.count);
		}
		/* 0/2: 38 => 3/1; 3a => 2/1; */
		show_tree_range(&inode->btree, 0, -1);
		struct delete_info delinfo = { .key = 0, };
		segs = tree_chop(&inode->btree, &delinfo, 0);
		assert(!segs);
		segs = map_region(inode, 0, INT_MAX, &seg, 1, 0);
		assert(segs == 1 && seg.count == INT_MAX && seg.state == SEG_HOLE);
		sb->nextalloc = nextalloc;
	}

#if 1
	sb->nextalloc = 0x10;
	balloc(sb, 1);
	sb->nextalloc = 0xf;
	brelse_dirty(blockread(mapping(inode), 0x0));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	brelse_dirty(blockread(mapping(inode), 0x1));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	evict_buffers(mapping(inode));
	filemap_extent_io(blockget(mapping(inode), 1), 0);
	exit(0);
#endif

#if 1
	filemap_extent_io(blockget(mapping(inode), 5), 0);
	exit(0);
#endif

#if 0
	for (int i = 0; i < 20; i++) {
		brelse_dirty(blockget(mapping(inode), i));
		printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));
	}
	return 0;
#endif

#if 1
	brelse_dirty(blockget(mapping(inode), 5));
	brelse_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	brelse_dirty(blockget(mapping(inode), 6));
	brelse_dirty(blockget(mapping(inode), 7));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	exit(0);
#endif

	brelse_dirty(blockget(mapping(inode), 0));
	brelse_dirty(blockget(mapping(inode), 1));
	brelse_dirty(blockget(mapping(inode), 2));
	brelse_dirty(blockget(mapping(inode), 3));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	brelse_dirty(blockget(mapping(inode), 0));
	brelse_dirty(blockget(mapping(inode), 1));
	brelse_dirty(blockget(mapping(inode), 2));
	brelse_dirty(blockget(mapping(inode), 3));
	brelse_dirty(blockget(mapping(inode), 4));
	brelse_dirty(blockget(mapping(inode), 5));
	brelse_dirty(blockget(mapping(inode), 6));
	printf("flush... %s\n", strerror(-flush_buffers(mapping(inode))));

	//show_buffers(mapping(inode));
	
	exit(0);
}
#endif
