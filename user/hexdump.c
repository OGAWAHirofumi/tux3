/* Copyright (c) 2008 Daniel Phillips <phillips@phunq.net>, GPL v3 */

#ifndef HEXDUMP
#define HEXDUMP

#include "tux3.h"

#ifndef __KERNEL__
#include <execinfo.h>

void stacktrace(void)
{
	void *array[100];
	size_t size = backtrace(array, 100);
	printf("_______stack ______\n");
	backtrace_symbols_fd(array, size, 2);
}
#endif

#include "kernel/hexdump.c"
#endif
