#include <inttypes.h>
#include <sys/types.h>

int diskread(int fd, void *data, size_t count, off_t offset);
int diskwrite(int fd, void *data, size_t count, off_t offset);
int streamread(int fd, void *data, size_t count);
int streamwrite(int fd, void *data, size_t count);
uint64_t fdsize64(int fd);

