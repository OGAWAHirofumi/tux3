#ifndef TRACE_H
#define TRACE_H

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <execinfo.h>
#include <unistd.h> // getpid
#include <stdarg.h>

static inline void logline(const char *caller, const char *fmt, ...)
{
	printf("%s: ", caller);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

//#define die(code) exit(code)
#define die(code) asm("int3")
#define error(string, args...) ({ warn(string "!", ##args); die(99); 1; })
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define warn(string, args...) do { logline(__func__, string, ##args); } while (0)
#define trace_off(...) do {} while (0)
#define trace_on(fmt, args...) warn(fmt, ## args)

#endif
