#include <string.h>
#include <stdio.h>
#include <time.h>
#include <execinfo.h>
#include <unistd.h> // getpid

//#define die(code) exit(code)
#define die(code) asm("int3")
#define warn(string, args...) do {\
	time_t _warn_time = time(NULL);\
	char *_warn_ctime = ctime(&_warn_time);\
	if (_warn_ctime[strlen(_warn_ctime)-1] == '\n')\
		_warn_ctime[strlen(_warn_ctime)-1] = '\0';\
	fprintf(stderr, "%s: [%u] %s: " string "\n", _warn_ctime, getpid(), __func__, ##args);\
	} while (0)

#define error(string, args...) do { warn(string, ##args); die(99); } while (0) 
#define assert(expr) do { if (!(expr)) error("Failed assertion \"%s\"\n", #expr); } while (0)

#define trace_on(args) args
#define trace_off(args)
