#ifndef LIBKLIB_SLAB_H
#define LIBKLIB_SLAB_H

#include <libklib/mm.h>

/*
 * Flags to pass to kmem_cache_create().
 * The ones marked DEBUG are only valid if CONFIG_SLAB_DEBUG is set.
 */
#define SLAB_DEBUG_FREE		0x00000100UL	/* DEBUG: Perform (expensive) checks on free */
#define SLAB_RED_ZONE		0x00000400UL	/* DEBUG: Red zone objs in a cache */
#define SLAB_POISON		0x00000800UL	/* DEBUG: Poison objects */
#define SLAB_HWCACHE_ALIGN	0x00002000UL	/* Align objs on cache lines */
#define SLAB_CACHE_DMA		0x00004000UL	/* Use GFP_DMA memory */
#define SLAB_STORE_USER		0x00010000UL	/* DEBUG: Store the last owner for bug hunting */
#define SLAB_PANIC		0x00040000UL	/* Panic if kmem_cache_create() fails */
/*
 * SLAB_DESTROY_BY_RCU - **WARNING** READ THIS!
 *
 * This delays freeing the SLAB page by a grace period, it does _NOT_
 * delay object freeing. This means that if you do kmem_cache_free()
 * that memory location is free to be reused at any time. Thus it may
 * be possible to see another object there in the same RCU grace period.
 *
 * This feature only ensures the memory location backing the object
 * stays valid, the trick to using this is relying on an independent
 * object validation pass. Something like:
 *
 *  rcu_read_lock()
 * again:
 *  obj = lockless_lookup(key);
 *  if (obj) {
 *    if (!try_get_ref(obj)) // might fail for free objects
 *      goto again;
 *
 *    if (obj->key != key) { // not the object we expected
 *      put_ref(obj);
 *      goto again;
 *    }
 *  }
 *  rcu_read_unlock();
 *
 * See also the comment on struct slab_rcu in mm/slab.c.
 */
#define SLAB_DESTROY_BY_RCU	0x00080000UL	/* Defer freeing slabs to RCU */
#define SLAB_MEM_SPREAD		0x00100000UL	/* Spread some memory over cpuset */
#define SLAB_TRACE		0x00200000UL	/* Trace allocations and frees */

/* Flag to prevent checks on free */
#ifdef CONFIG_DEBUG_OBJECTS
# define SLAB_DEBUG_OBJECTS	0x00400000UL
#else
# define SLAB_DEBUG_OBJECTS	0x00000000UL
#endif

#define SLAB_NOLEAKTRACE	0x00800000UL	/* Avoid kmemleak tracing */

/* Don't track use of uninitialized memory */
#ifdef CONFIG_KMEMCHECK
# define SLAB_NOTRACK		0x01000000UL
#else
# define SLAB_NOTRACK		0x00000000UL
#endif
#ifdef CONFIG_FAILSLAB
# define SLAB_FAILSLAB		0x02000000UL	/* Fault injection mark */
#else
# define SLAB_FAILSLAB		0x00000000UL
#endif

/* The following flags affect the page allocator grouping pages by mobility */
#define SLAB_RECLAIM_ACCOUNT	0x00020000UL		/* Objects are reclaimable */
#define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */

struct kmem_cache {
	unsigned int object_size;	/* The original size of the object */
	unsigned int align;		/* Alignment as calculated */
	unsigned long flags;		/* Active flags on the slab */
	const char *name;		/* Slab name for sysfs */
	void (*ctor)(void *);		/* Called on object slot creation */
};

struct kmem_cache *kmem_cache_create(const char *, size_t, size_t,
				     unsigned long,
				     void (*)(void *));
void kmem_cache_destroy(struct kmem_cache *);
void kmem_cache_free(struct kmem_cache *, void *);

void *kmem_cache_alloc(struct kmem_cache *, gfp_t);

/*
 * Shortcuts
 */
static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
	return kmem_cache_alloc(k, flags | __GFP_ZERO);
}

#endif /* !LIBKLIB_SLAB_H */
