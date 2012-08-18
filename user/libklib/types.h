#ifndef LIBKLIB_TYPES_H
#define LIBKLIB_TYPES_H

#include <libklib/compiler.h>

typedef unsigned short		umode_t;

typedef signed char		__s8;
typedef unsigned char		__u8;
typedef signed short		__s16;
typedef unsigned short		__u16;
typedef signed int		__s32;
typedef unsigned int		__u32;
typedef signed long long	__s64;
typedef unsigned long long	__u64;

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

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef unsigned __bitwise__ gfp_t;

#endif /* !LIBKLIB_TYPES_H */
