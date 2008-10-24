#include <inttypes.h>
#include <sys/types.h>

int diskread(int fd, void *data, size_t count, off_t offset);
int diskwrite(int fd, void *data, size_t count, off_t offset);
int streamread(int fd, void *data, size_t count);
int streamwrite(int fd, void *data, size_t count);
int fdsize64(int fd, uint64_t *size);

