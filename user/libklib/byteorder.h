#ifndef LIBKLIB_BYTEORDER_H
#define LIBKLIB_BYTEORDER_H

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#include <libklib/byteorder/little_endian.h>
#elif __BYTE_ORDER == __BIG_ENDIAN
#include <libklib/byteorder/big_endian.h>
#else
#error "Unknown byte order"
#endif

#endif /* !LIBKLIB_BYTEORDER_H */
