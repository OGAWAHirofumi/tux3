/*
 * Provide current->journal_info.
 */

#include "tux3user.h"

__thread struct task_struct current_task = {};
