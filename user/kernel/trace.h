#ifndef TRACE_H
#define TRACE_H

#ifdef __KERNEL__
extern int tux3_trace;
#define assert(expr)	BUG_ON(!(expr))
#else
#define tux3_trace	1
#endif

#define logline(caller, fmt, args...)	do {		\
	printf("%s: " fmt "\n" , caller , ##args);	\
} while (0)

#define error(fmt, args...) ({ warn(fmt "!" , ##args); die(99); 1; })
#define warn(fmt, args...) do { logline(__func__, fmt , ##args); } while (0)
#define trace_off(...) do {} while (0)
#define trace_on(fmt, args...) do {		\
	if (tux3_trace)				\
		warn(fmt , ##args);		\
} while (0)

/*
 * FIXME: this may want to change behavior by mount option.
 * NOTE: don't assume this calls die().
 */
#define tux_error(sb, fmt, args...) do {	\
	warn(fmt , ##args);			\
	die(100);				\
} while (0)

#endif
