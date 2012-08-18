#ifndef LIBKLIB_COMPILER_H
#define LIBKLIB_COMPILER_H

#ifdef __CHECKER__
#define __force		__attribute__((force))
#define __bitwise__	__attribute__((bitwise))
#else
#define __force
#define __bitwise__
#endif

#ifdef __GNUC__
#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))

#if __GNUC__ < 3
/* gcc 2.x */
#elif __GNUC__ == 3
/* gcc 3.x */
#if __GNUC_MINOR__ >= 4
#define __must_check	__attribute__((warn_unused_result))
#endif
#elif __GNUC__ == 4
/* gcc 4.x */
#define __must_check	__attribute__((warn_unused_result))
#else
#warn "Unknown gcc version"
#endif

/*
 * A trick to suppress uninitialized variable warning without generating any
 * code
 */
#define uninitialized_var(x) x = x
#else /* !__GNUC__ */
#define uninitialized_var(x) x
#endif /* !__GNUC__ */

#ifndef __must_check
#define __must_check
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#endif /* !LIBKLIB_COMPILER_H */
