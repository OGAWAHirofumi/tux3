#ifndef TRACE_H
#define TRACE_H

#ifdef __KERNEL__
#define printf		printk
#define vprintf		vprintk

#define die(code) BUG_ON(1)
#endif

#define logline(caller, fmt, args...)	do {	\
	printf("%s: ", caller);			\
	printf(fmt , ##args);			\
	printf("\n");				\
} while (0)

#define error(string, args...) ({ warn(string "!", ##args); die(99); 1; })
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define warn(string, args...) do { logline(__func__, string, ##args); } while (0)
#define trace_off(...) do {} while (0)
#define trace_on(fmt, args...) warn(fmt, ## args)

#endif
