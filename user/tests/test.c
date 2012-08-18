#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>

#include "test.h"

#define TEST_NEST_MAX		10

struct test_env {
	const char *series;
	int test_fail_count;

	struct {
		const char *name;
		pid_t child;
		struct timeval start;
		int fail_cnt;
	} test[TEST_NEST_MAX];
	int nest;
	int forked;
};

static struct test_env test_env;

void test_init(const char *argv0)
{
	test_env.series = strrchr(argv0, '/');
	if (test_env.series == NULL)
		test_env.series = argv0;
	else
		test_env.series++;

	test_env.test_fail_count = 0;
	test_env.nest = -1;
	test_env.forked = 0;
}

const char *test_series(void)
{
	return test_env.series;
}

const char *test_name(void)
{
	return test_env.test[test_env.nest].name;
}

void test_assert_failed(void)
{
	test_env.test[test_env.nest].fail_cnt++;
}

int test_start(const char *test)
{
	int nest = ++test_env.nest;
	assert(nest < TEST_NEST_MAX);

	test_env.test[nest].name = test;

	test_env.test[nest].child = fork();
	assert(test_env.test[nest].child >= 0);
	if (test_env.test[nest].child == 0) {
		test_env.test[nest].fail_cnt = 0;
		gettimeofday(&test_env.test[nest].start, NULL);
		return 1;
	}

	test_env.forked = 1;
	return 0;
}

void test_end(void)
{
	int nest = test_env.nest;
	int test_fail_count = test_env.test_fail_count;
	pid_t err;
	int status;

	/* Dead as child? */
	if (!test_env.forked) {
		struct timeval end, diff;
		gettimeofday(&end, NULL);
		timersub(&end, &test_env.test[nest].start, &diff);

		printf("[%s:%s] time %3ld.%06ld secs\n",
		       test_env.series, test_env.test[nest].name,
		       diff.tv_sec, diff.tv_usec);

		exit(!!test_env.test[nest].fail_cnt);
	}

	test_env.forked = 0;
	err = waitpid(test_env.test[nest].child, &status, 0);
	assert(err >= 0);

	if (WIFEXITED(status)) {
		printf("[%s:%s] %s\n",
		       test_env.series, test_env.test[nest].name,
		       WEXITSTATUS(status) ? "FAILED" : "OK");

		if (WEXITSTATUS(status))
			test_env.test_fail_count++;
	} else if (WIFSIGNALED(status)) {
		printf("[%s:%s] FAILED by sig (%d)%s\n",
		       test_env.series, test_env.test[nest].name,
		       WTERMSIG(status), WCOREDUMP(status) ? " coredump" : "");

		if (WCOREDUMP(status)) {
			char corename[4096];
			snprintf(corename, sizeof(corename), "%s.%s.core",
				 test_env.series, test_env.test[nest].name);
			rename("core", corename);
		}

		test_env.test_fail_count++;
	}

	test_env.nest--;
	/* If nexted test failed, propagate failure to parent */
	if (test_env.test_fail_count > test_fail_count)
		test_assert_failed();
}

int test_failures(void)
{
	return test_env.test_fail_count;
}

/*
 * Utility functions for test
 */

/* Create shared memory to share with child process */
void *test_alloc_shm(size_t size)
{
	void *ptr;

	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	assert(ptr != MAP_FAILED);

	return ptr;
}

void test_free_shm(void *ptr, size_t size)
{
	munmap(ptr, size);
}
