#ifndef USER_TRACE_H
#define USER_TRACE_H

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <execinfo.h>
#include <stdarg.h>

//#define die(code) exit(code)
#define die(code)	do { int *__p = NULL; *__p = code; } while (0)
#define assert(expr)	do {						\
	if (!(expr)) {							\
		fprintf(stderr, "%s:%d: Failed assert(" #expr ")\n",	\
			__func__, __LINE__);				\
		die(99);						\
	}								\
} while (0)

#include "kernel/trace.h"

#endif /* !USER_TRACE_H */
