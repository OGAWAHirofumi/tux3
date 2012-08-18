#include "tux3user.h"

#include "buffer.c"
#include "diskio.c"
#include "hexdump.c"

#ifndef trace
#define trace trace_on
#endif

#include "kernel/utility.c"

int devio(int rw, struct dev *dev, loff_t offset, void *data, unsigned len)
{
	return ioabs(dev->fd, data, len, rw, offset);
}

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	trace("%s: buffer %p, block %Lx", rw ? "write" : "read",
	      buffer, (L)block);
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
	return devio(rw, sb_dev(sb), block << sb->blockbits, bufdata(buffer),
		     sb->blocksize);
}
