#ifndef TUX3_LINK_H
#define TUX3_LINK_H

/* Single linked list support (LIFO order) */

struct link { struct link *next; };

#define LINK_INIT_CIRCULAR(name)	{ &(name), }
#define link_entry(ptr, type, member)	container_of(ptr, type, member)
/* take care: this doesn't check member is `struct link *' or not */
#define __link_entry(ptr, type, member) \
	container_of((typeof(((type *)0)->member) *)ptr, type, member)

static inline void init_link_circular(struct link *head)
{
	head->next = head;
}

static inline int link_empty(const struct link *head)
{
	return head->next == head;
}

static inline void link_add(struct link *node, struct link *head)
{
	node->next = head->next;
	head->next = node;
}

static inline void link_del_next(struct link *node)
{
	node->next = node->next->next;
}

#define link_for_each_safe(pos, prev, n, head)			\
        for (pos = (head)->next, prev = (head), n = pos->next;  \
	     pos != (head);					\
	     prev = ((prev->next == n) ? prev : pos), pos = n, n = pos->next)

/* Single linked list support (FIFO order) */

struct flink_head { struct link *tail; };

#define FLINK_HEAD_INIT(name)	{ NULL, }
#define flink_next_entry(head, type, member) \
	link_entry(flink_next(head), type, member)
/* take care: this doesn't check member is `struct link *' or not */
#define __flink_next_entry(head, type, member) ({			\
	struct link *next = flink_next(head);	       			\
	link_entry((typeof(((type *)0)->member) *)next, type, member);	\
})

static inline void init_flink_head(struct flink_head *head)
{
	head->tail = NULL;
}

static inline int flink_empty(const struct flink_head *head)
{
	return head->tail == NULL;
}

static inline int flink_is_last(const struct flink_head *head)
{
	return link_empty(head->tail);
}

static inline struct link *flink_next(const struct flink_head *head)
{
	return head->tail->next;
}

static inline void flink_first_add(struct link *node, struct flink_head *head)
{
	assert(flink_empty(head));
	init_link_circular(node);
	head->tail = node;
}

static inline void flink_add(struct link *node, struct flink_head *head)
{
	link_add(node, head->tail);
	head->tail = node;
}

static inline void flink_del_next(struct flink_head *head)
{
	link_del_next(head->tail);
}

static inline void flink_last_del(struct flink_head *head)
{
	assert(flink_is_last(head));
	init_flink_head(head);
}
#endif /* !TUX3_LINK_H */
