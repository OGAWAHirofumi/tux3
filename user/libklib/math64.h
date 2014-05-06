#ifndef LIBKLIB_MATH64_H
#define LIBKLIB_MATH64_H

#include <libklib/types.h>

static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

#endif /* !LIBKLIB_MATH64_H */
