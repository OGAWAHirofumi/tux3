#ifndef LIBKLIB_COMPILER_H
#define LIBKLIB_COMPILER_H

#ifdef __CHECKER__
#define __force		__attribute__((force))
#define __bitwise__	__attribute__((bitwise))
#define __kernel	__attribute__((address_space(0)))
#define __rcu		__attribute__((noderef, address_space(4)))
#else
#define __force
#define __bitwise__
#define __kernel
#define __rcu
#endif

#ifdef __GNUC__
#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))

#ifndef __attribute_const__
#define __attribute_const__		__attribute__((__const__))
#endif

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

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

/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * This macro does absolutely -nothing- to prevent the CPU from reordering,
 * merging, or refetching absolutely anything at any time.  Its main intended
 * use is to mediate communication between process-level code and irq/NMI
 * handlers, all running on the same CPU.
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#endif /* !LIBKLIB_COMPILER_H */
