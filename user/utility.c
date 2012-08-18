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

int devio_vec(int rw, struct dev *dev, loff_t offset, struct iovec *iov,
	      unsigned iovcnt)
{
	return iovabs(dev->fd, iov, iovcnt, rw, offset);
}

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	trace("%s: buffer %p, block %Lx", rw ? "write" : "read",
	      buffer, block);
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
	return devio(rw, sb_dev(sb), block << sb->blockbits, bufdata(buffer),
		     sb->blocksize);
}

int blockio_vec(int rw, struct bufvec *bufvec, block_t block, unsigned count)
{
	trace("%s: bufvec %p, count %u, block %Lx", rw ? "write" : "read",
	      bufvec, count, block);
	return bufvec_io(rw, bufvec, block, count);
}
