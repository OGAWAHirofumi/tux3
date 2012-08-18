#ifndef TUX3_DISKIO_H
#define TUX3_DISKIO_H

#include <inttypes.h>
#include <sys/types.h>

int ioabs(int fd, void *data, size_t count, int out, off_t offset);
int diskread(int fd, void *data, size_t count, off_t offset);
int diskwrite(int fd, void *data, size_t count, off_t offset);
int streamread(int fd, void *data, size_t count);
int streamwrite(int fd, void *data, size_t count);
int fdsize64(int fd, loff_t *size);

#endif /* !TUX3_DISKIO_H */
