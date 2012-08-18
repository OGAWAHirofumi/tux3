#ifndef LIBKLIB_TYPES_H
#define LIBKLIB_TYPES_H

#include <libklib/compiler.h>

typedef unsigned short		umode_t;

typedef signed char		s8;
typedef unsigned char		u8;
typedef signed short		s16;
typedef unsigned short		u16;
typedef signed int		s32;
typedef unsigned int		u32;
typedef signed long long	s64;
typedef unsigned long long	u64;

#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef unsigned __bitwise__ gfp_t;

#endif /* !LIBKLIB_TYPES_H */
