#include <string.h>
#include <stdio.h>
#include <time.h>
#include <execinfo.h>
#include <unistd.h> // getpid

//#define die(code) exit(code)
#define die(code) asm("int3")
#define warn(string, args...) do {\
	fprintf(stderr, "%s: " string "\n", __func__, ##args);\
} while (0)

#define error(string, args...) do { warn(string, ##args); die(99); } while (0) 
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"\n", #expr); } while (0)

#define trace_on(args) args
#define trace_off(args)
