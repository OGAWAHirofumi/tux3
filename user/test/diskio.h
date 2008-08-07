#include <inttypes.h>
#include <sys/types.h>

int diskread(int fd, void *data, size_t count, off_t offset);
int diskwrite(int fd, void const *data, size_t count, off_t offset);
int fdread(int fd, void *data, size_t count);
int fdwrite(int fd, void const *data, size_t count);
int is_same_device(char const *dev1,char const *dev2);
uint64_t fdsize64(int fd);

