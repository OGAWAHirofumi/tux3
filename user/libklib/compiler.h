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

/*
 * A trick to suppress uninitialized variable warning without generating any
 * code
 */
#define uninitialized_var(x) x = x
#else /* !__GNUC__ */
#define uninitialized_var(x) x
#endif /* !__GNUC__ */

#endif /* !LIBKLIB_COMPILER_H */
