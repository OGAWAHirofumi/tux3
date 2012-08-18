#ifndef LIBKLIB_BITOPS_H
#define LIBKLIB_BITOPS_H

#include <limits.h>

#define BITS_PER_LONG		LONG_BIT	/* SuS define this */

#define BIT(nr)			(1UL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#include <libklib/bitops/__ffs.h>
#include <libklib/bitops/ffz.h>
#include <libklib/bitops/find.h>
#include <libklib/bitops/le.h>

#endif /* !LIBKLIB_BITOPS_H */
