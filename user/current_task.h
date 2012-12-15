#ifndef TUX3_CURRENT_TASK_H
#define TUX3_CURRENT_TASK_H

struct task_struct {
	void *journal_info;
};

extern __thread struct task_struct current_task;
static inline struct task_struct *get_current(void)
{
	return &current_task;
}

#define current		get_current()

#endif /* !_CURRENT_TASK_H */
