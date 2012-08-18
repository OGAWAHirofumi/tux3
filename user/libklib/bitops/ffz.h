#ifndef LIBKLIB_BITOPS_FFZ_H
#define LIBKLIB_BITOPS_FFZ_H

/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))

#endif /* !LIBKLIB_BITOPS_FFZ_H */
