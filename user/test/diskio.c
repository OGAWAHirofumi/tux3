#define _XOPEN_SOURCE 500 /* pwrite */
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/fs.h> // for BLKGETSIZE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "trace.h"
#include "diskio.h"

#undef DEBUG_FDIO_FAIL
#undef DEBUG_FDIO_SHORT

/* Sane [p]read/[p]write wrapper */

static int fdio(int fd, void *data, size_t count, int use_offset, off_t offset, int do_write)
{
	while (count) {
		ssize_t ret;

		if (use_offset)
			if (do_write)
				ret = pwrite(fd, data, count, offset);
			else
				ret = pread(fd, data, count, offset);
		else
			if (do_write)
				ret = write(fd, data, count);
			else
				ret = read(fd, data, count);


		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;

#ifdef DEBUG_FDIO_FAIL
			char const *op;

			if (use_offset)
				if (do_write)
					op = "pwrite";
				else
					op = "pread";
			else
				if (do_write)
					op = "write";
				else
					op = "read";

			warn("%s failed %s", op, strerror(errno));
#endif
			return -errno;
		}

		if (ret == 0) {
#ifdef DEBUG_FDIO_SHORT
			char const *op;

			if (use_offset)
				if (do_write)
					op = "pwrite";
				else
					op = "pread";
			else
				if (do_write)
					op = "write";
				else
					op = "read";

			warn("short %s", op);
#endif
			return -EIO;
		}

		data += ret; /* not portable but GCC treats like char * */
		count -= ret;

		offset += ret;
	}

	return 0;
}

#if 0
int diskio(int fd, void *data, size_t count, int use_offset, off_t offset, int do_write)
{
	return fdio(fd, data, count, 1, offset, do_write);
}
#endif

int diskread(int fd, void *data, size_t count, off_t offset)
{
	return fdio(fd, data, count, 1, offset, 0);
}

int diskwrite(int fd, void const *data, size_t count, off_t offset)
{
	return fdio(fd, (void *)data, count, 1, offset, 1);
}

int fdread(int fd, void *data, size_t count)
{
	return fdio(fd, data, count, 0, 0, 0);
}

int fdwrite(int fd, void const *data, size_t count)
{
	return fdio(fd, (void *)data, count, 0, 0, 1);
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

int is_same_device(char const *dev1,char const *dev2) {
	struct stat stat1, stat2;

	if (stat(dev1, &stat1) < 0) {
		warn("could not stat %s", dev1);
		return -1;
	}

	if (stat(dev2, &stat2) < 0) {
		warn("could not stat %s", dev2);
		return -1;
	}

	if (!S_ISBLK(stat1.st_mode) && !S_ISREG(stat1.st_mode)) {
		fprintf(stderr, "device %s is not a block device\n", dev1);
		return -1;
	}

	if (!S_ISBLK(stat2.st_mode) && !S_ISREG(stat2.st_mode)) {
		fprintf(stderr, "device %s is not a block device\n", dev2);
		return -1;
	}

	if (S_ISBLK(stat1.st_mode) != S_ISBLK(stat2.st_mode))
		return 0;

	if (S_ISREG(stat1.st_mode) && stat1.st_ino != stat2.st_ino)
		return 0;

	if (stat1.st_rdev != stat2.st_rdev)
		return 0;

	warn("device %s is the same as %s\n", dev1, dev2);
	return 1;
}
