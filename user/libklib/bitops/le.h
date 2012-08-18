#ifndef LIBKLIB_BITOPS_LE_H
#define LIBKLIB_BITOPS_LE_H

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define BITOP_LE_SWIZZLE	0

static inline unsigned long find_next_zero_bit_le(const void *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_zero_bit(addr, size, offset);
}

static inline unsigned long find_next_bit_le(const void *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_bit(addr, size, offset);
}

static inline unsigned long find_first_zero_bit_le(const void *addr,
		unsigned long size)
{
	return find_first_zero_bit(addr, size);
}

#elif __BYTE_ORDER == __BIG_ENDIAN

#define BITOP_LE_SWIZZLE	((BITS_PER_LONG-1) & ~0x7)

extern unsigned long find_next_zero_bit_le(const void *addr,
		unsigned long size, unsigned long offset);

extern unsigned long find_next_bit_le(const void *addr,
		unsigned long size, unsigned long offset);

#define find_first_zero_bit_le(addr, size) \
	find_next_zero_bit_le((addr), (size), 0)

#else
#error "Unknown byte order"
#endif

#endif /* !LIBKLIB_BITOPS_LE_H */
