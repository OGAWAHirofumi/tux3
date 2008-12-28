#ifndef TRACE_H
#define TRACE_H

#define logline(caller, fmt, args...)	do {	\
	printf("%s: ", caller);			\
	printf(fmt , ##args);			\
	printf("\n");				\
} while (0)

#define error(fmt, args...) ({ warn(fmt "!" , ##args); die(99); 1; })
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"", #expr); } while (0)
#define warn(fmt, args...) do { logline(__func__, fmt , ##args); } while (0)
#define trace_off(...) do {} while (0)
#define trace_on(fmt, args...) warn(fmt , ##args)

/*
 * FIXME: this may want to change behavior by mount option.
 * NOTE: don't assume this calls die().
 */
#define tux_error(sb, fmt, args...) do {	\
	warn(fmt , ##args);			\
	die(100);				\
} while (0)

#endif
