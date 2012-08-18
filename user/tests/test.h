#ifndef _TEST_H
#define _TEST_H

#include <sys/time.h>
#include <sys/types.h>

#define test_assert(x)	({						\
	int __test_res = !(x);						\
	if (__test_res) {						\
		printf("%s: %s:%d:%s: assertion failed: %s\n",		\
		       test_series(), __FILE__, __LINE__,		\
		       __func__, #x);					\
		test_assert_failed();					\
	}								\
	__test_res;							\
})

void test_init(const char *argv0);
const char *test_series(void);
void test_assert_failed(void);
int test_start(const char *name);
void test_end(void);
int test_failures(void);
void *test_alloc_shm(size_t size);
void test_free_shm(void *ptr, size_t size);

#endif /* !_TEST_H */
