#include <stdio.h>
#include <stdlib.h>

#include <tux3user.h>
#include <libklib/libklib.h>
#include <libklib/slab.h>

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
				     size_t align, unsigned long flags,
				     void (*ctor)(void *))
{
	struct kmem_cache *cachep;

	cachep = malloc(sizeof(*cachep));
	if (cachep) {
		cachep->name		= name;
		cachep->object_size	= size;
		cachep->align		= align;
		cachep->flags		= flags;
		cachep->ctor		= ctor;
	}
	return cachep;
}

void kmem_cache_destroy(struct kmem_cache *cachep)
{
	free(cachep);
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	free(objp);
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;

	if (cachep->align) {
		int err;
		err = posix_memalign(&objp, cachep->align, cachep->object_size);
		if (err)
			objp = NULL;
	} else
		objp = malloc(cachep->object_size);

	if (objp) {
		if (cachep->ctor)
			cachep->ctor(objp);
		if (flags & __GFP_ZERO)
			memset(objp, 0, cachep->object_size);
	}

	return objp;
}
