#include "buffer.c"
#include "diskio.c"
#include "hexdump.c"

void set_bits(uint8_t *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		bitmap[loff] |= lmask & rmask;
		return;
	}
	bitmap[loff] |= lmask;
	memset(bitmap + loff + 1, -1, roff - loff - 1);
	if (rmask)
		bitmap[roff] |= rmask;
}

void clear_bits(uint8_t *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		bitmap[loff] &= ~lmask | ~rmask;
		return;
	}
	bitmap[loff] &= ~lmask;
	memset(bitmap + loff + 1, 0, roff - loff - 1);
	if (rmask)
		bitmap[roff] &= ~rmask;
}

int all_set(uint8_t *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		unsigned mask = lmask & rmask;
		return (bitmap[loff] & mask) == mask;
	}
	for (unsigned i = loff + 1; i < roff; i++)
		if (bitmap[i] != 0xff)
			return 0;
	return	(bitmap[loff] & lmask) == lmask &&
		(!rmask || (bitmap[roff] & rmask) == rmask);
}

int all_clear(uint8_t *bitmap, unsigned start, unsigned count) // untested
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		unsigned mask = lmask & rmask;
		return !(bitmap[loff] & mask);
	}
	for (unsigned i = loff + 1; i < roff; i++)
		if (bitmap[i])
			return 0;
	return	!(bitmap[loff] & lmask) &&
		(!rmask || !(bitmap[roff] & rmask));
}

int bytebits(uint8_t c)
{
	unsigned count = 0;

	for (; c; c >>= 1)
		count += c & 1;
	return count;
}
