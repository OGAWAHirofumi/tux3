#ifndef LIBKLIB_WAIT_H
#define LIBKLIB_WAIT_H

#include <libklib/typecheck.h>

/*
 * Provide wait queue stabs
 */

struct __wait_queue {
};
typedef struct __wait_queue wait_queue_t;

struct __wait_queue_head {
};
typedef struct __wait_queue_head wait_queue_head_t;

#define __WAITQUEUE_INITIALIZER(name, tsk)	{}

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name)	{}

#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

#define init_waitqueue_head(q)				\
do {							\
	typecheck(wait_queue_head_t *, q);		\
} while (0)

#define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)

#define __wake_up(q, mode, nr, key)			\
do {							\
	typecheck(wait_queue_head_t *, q);		\
} while (0)

#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)

#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)

#define __wait_event(wq, condition) 					\
do {									\
	typecheck(wait_queue_head_t, wq);				\
	for (;;) {							\
		if (condition)						\
			break;						\
	}								\
} while (0)

#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)

#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event(wq, condition);				\
	__ret;								\
})

#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event(wq, condition);				\
	__ret;								\
})

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event(wq, condition);				\
	__ret;								\
})

#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event(wq, condition);				\
	__ret;								\
})

#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event(wq, condition);				\
	__ret;								\
})

#endif /* !LIBKLIB_WAIT_H */
