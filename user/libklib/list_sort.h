#ifndef LIBKLIB_LIST_SORT_H
#define LIBKLIB_LIST_SORT_H

#include <libklib/types.h>

struct list_head;

void list_sort(void *priv, struct list_head *head,
	       int (*cmp)(void *priv, struct list_head *a,
			  struct list_head *b));

#endif /* !LIBKLIB_LIST_SORT_H */
