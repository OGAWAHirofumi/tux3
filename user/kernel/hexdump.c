/* Copyright (c) 2008, 2009 Daniel Phillips <phillips@phunq.net>, GPL v2 */

#include <linux/kernel.h>

void hexdump(void *data, unsigned size)
{
	while (size) {
		unsigned char *p;
		int w = 16, n = size < w? size: w, pad = w - n;
		printk("%p:  ", data);
		for (p = data; p < (unsigned char *)data + n;)
			printk("%02hx ", *p++);
		printk("%*.s  \"", pad*3, "");
		for (p = data; p < (unsigned char *)data + n;) {
			int c = *p++;
			printk("%c", c < ' ' || c > 127 ? '.' : c);
		}
		printk("\"\n");
		data += w;
		size -= n;
	}
}
