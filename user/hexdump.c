/* Copyright (c) 2008 Daniel Phillips <phillips@phunq.net>, GPL v3 */

#ifndef HEXDUMP
#define HEXDUMP

#include "tux3.h"

void hexdump(void *data, unsigned size)
{
	while (size) {
		unsigned char *p;
		int w = 16, n = size < w? size: w, pad = w - n;
		printf("%p:  ", data);
		for (p = data; p < (unsigned char *)data + n;)
			printf("%02hx ", *p++);
		printf("%*.s  \"", pad*3, "");
		for (p = data; p < (unsigned char *)data + n;) {
			int c = *p++;
			printf("%c", c < ' ' || c > 127 ? '.' : c);
		}
		printf("\"\n");
		data += w;
		size -= n;
	}
}

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
#endif
