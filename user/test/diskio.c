#define _XOPEN_SOURCE 500 /* pwrite */
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/fs.h> // for BLKGETSIZE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "trace.h"
#include "diskio.h"

static int ioabs(int fd, void *data, size_t count, int out, off_t offset)
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

int diskwrite(int fd, void const *data, size_t count, off_t offset)
{
	return ioabs(fd, (void *)data, count, 1, offset);
}

int streamread(int fd, void *data, size_t count)
{
	return iorel(fd, data, count, 0);
}

int streamwrite(int fd, void const *data, size_t count)
{
	return iorel(fd, (void *)data, count, 1);
}

uint64_t fdsize64(int fd)
{
	uint64_t bytes;
	struct stat stat;

	if (fstat(fd, &stat) == -1)
		return -1;

	if (S_ISREG(stat.st_mode))
		return stat.st_size;

	if (ioctl(fd, BLKGETSIZE64, &bytes))
		return -1;

	return bytes;
}
