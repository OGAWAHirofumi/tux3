#ifndef TUX3_FORK_H
#define TUX3_FORK_H

#ifdef __KERNEL__
#include <linux/log2.h>
#else
#include <libklib/log2.h>
#endif

/*
 * Helpers for the data forking state
 */

#define TUX3_DEFINE_STATE_FNS(type, name, avail_base, bits, shift)	\
static inline type tux3_##name##sta_mask(void)				\
{									\
	type mask = (1 << (bits)) - 1;					\
	return mask << (shift);						\
}									\
									\
static inline type tux3_##name##sta(type state)				\
{									\
	return (state & tux3_##name##sta_mask()) >> (shift);		\
}									\
									\
static inline type tux3_##name##sta_has_delta(type state)		\
{									\
	return tux3_##name##sta(state) >= (avail_base);			\
}									\
									\
static inline type tux3_##name##sta_get_delta(type state)		\
{									\
	return tux3_##name##sta(state) - (avail_base);			\
}									\
									\
static inline type tux3_##name##sta_delta(unsigned delta)		\
{									\
	return ((avail_base) + tux3_delta(delta)) << (shift);		\
}									\
									\
static inline type tux3_##name##sta_clear(type state)			\
{									\
	return state & ~tux3_##name##sta_mask();			\
}									\
									\
static inline type tux3_##name##sta_update(type state, unsigned delta)	\
{									\
	return tux3_##name##sta_clear(state) | tux3_##name##sta_delta(delta); \
}

#endif /* !TUX3_FORK_H */
