#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/fs.h> // for BLKGETSIZE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "trace.h"
#include "diskio.h"

static ssize_t iov_length(struct iovec *iov, int iovcnt)
{
	ssize_t size = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		size += iov[i].iov_len;
	return size;
}

int iovabs(int fd, struct iovec *iov, int iovcnt, int out, off_t offset)
{
	while (1) {
		int count = min(iovcnt, UIO_MAXIOV);
		ssize_t ret;

		if (out)
			ret = pwritev(fd, iov, count, offset);
		else
			ret = preadv(fd, iov, count, offset);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		if (ret != iov_length(iov, count))
			return -EIO;
		if (iovcnt == count)
			break;

		iov += count;
		iovcnt -= count;
		offset += ret;
	}

	return 0;
}

int ioabs(int fd, void *data, size_t count, int out, off_t offset)
{
	while (count) {
		ssize_t ret;
		if (out)
			ret = pwrite(fd, data, count, offset);
		else
			ret = pread(fd, data, count, offset);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		if (ret == 0)
			return -EIO;
		data += ret;
		count -= ret;
		offset += ret;
	}
	return 0;
}

static int iorel(int fd, void *data, size_t count, int out)
{
	while (count) {
		ssize_t ret;
		if (out)
			ret = write(fd, data, count);
		else
			ret = read(fd, data, count);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		}
		if (ret == 0)
			return -EIO;
		data += ret;
		count -= ret;
	}
	return 0;
}

int diskread(int fd, void *data, size_t count, off_t offset)
{
	return ioabs(fd, data, count, 0, offset);
}

int diskwrite(int fd, void *data, size_t count, off_t offset)
{
	return ioabs(fd, data, count, 1, offset);
}

int streamread(int fd, void *data, size_t count)
{
	return iorel(fd, data, count, 0);
}

int streamwrite(int fd, void *data, size_t count)
{
	return iorel(fd, data, count, 1);
}

int fdsize64(int fd, loff_t *size)
{
	struct stat stat;
	if (fstat(fd, &stat))
		return -1;
	if (S_ISREG(stat.st_mode)) {
		*size = stat.st_size;
		return 0;
	}
	return ioctl(fd, BLKGETSIZE64, size);
}
