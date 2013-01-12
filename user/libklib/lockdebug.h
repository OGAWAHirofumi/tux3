#ifndef LIBKLIB_LOCKDEBUG_H
#define LIBKLIB_LOCKDEBUG_H

#define LOCK_DEBUG

#define SPINLOCK_MAGIC		0xdead4ead
typedef struct {
#ifdef LOCK_DEBUG
	unsigned int magic;
	int lock;
#endif
} spinlock_t;

#ifdef LOCK_DEBUG
#define __SPIN_LOCK_UNLOCKED \
	(spinlock_t){ .magic = SPINLOCK_MAGIC, .lock = 0, }
#else
#define __SPIN_LOCK_UNLOCKED \
	(spinlock_t){ }
#endif
#define DEFINE_SPINLOCK(x) spinlock_t x = __SPIN_LOCK_UNLOCKED
#define spin_lock_init(lock) do { *(lock) = SPIN_LOCK_UNLOCKED; } while (0)

static inline void spin_lock(spinlock_t *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->lock == 0);
	lock->lock++;
#endif
}
static inline void spin_unlock(spinlock_t *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->lock == 1);
	lock->lock--;
#endif
}

typedef struct {
	int counter;
} atomic_t;

#define ATOMIC_INIT(i)	{ (i) }
#define atomic_read(v)	((v)->counter)

static inline void atomic_inc(atomic_t *v)
{
	v->counter++;
}
static inline void atomic_dec(atomic_t *v)
{
	v->counter--;
}

static inline int atomic_dec_and_test(atomic_t *v)
{
	assert(v->counter > 0);
	return !--v->counter;
}

static inline int atomic_dec_and_lock(atomic_t *v, spinlock_t *lock)
{
	spin_lock(lock);
	if (atomic_dec_and_test(v))
		return 1;
	spin_unlock(lock);
	return 0;
}

struct rw_semaphore {
#ifdef LOCK_DEBUG
	unsigned int magic;
	int count;
#endif
};

#ifdef LOCK_DEBUG
#define __RWSEM_INITIALIZER \
	(struct rw_semaphore){ .magic = SPINLOCK_MAGIC, .count = 0, }
#else
#define __RWSEM_INITIALIZER \
	(struct rw_semaphore){ }
#endif
#define DECLARE_RWSEM(name) struct rw_semaphore name = __RWSEM_INITIALIZER
#define init_rwsem(sem) do { *(sem) = __RWSEM_INITIALIZER; } while (0)

static inline void down_read(struct rw_semaphore *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->count >= 0);
	lock->count++;
#endif
}
#define down_read_nested(lock, sub) down_read(lock)
static inline void down_write(struct rw_semaphore *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->count == 0);
	lock->count--;
#endif
}
#define down_write_nested(lock, sub) down_write(lock)
static inline void up_read(struct rw_semaphore *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->count >= 1);
	lock->count--;
#endif
}
static inline void up_write(struct rw_semaphore *lock)
{
#ifdef LOCK_DEBUG
	assert(lock->magic == SPINLOCK_MAGIC);
	assert(lock->count == -1);
	lock->count++;
#endif
}

struct mutex {
#ifdef LOCK_DEBUG
	struct rw_semaphore sem;
#endif
};

#ifdef LOCK_DEBUG
#define __MUTEX_INITIALIZER \
	(struct mutex){ .sem = __RWSEM_INITIALIZER, }
#else
#define __MUTEX_INITIALIZER \
	(struct mutex){ }
#endif
#define DEFINE_MUTEX(mutexname) struct mutex mutexname = __MUTEX_INITIALIZER
#define mutex_init(mutex) do { *(mutex) = __MUTEX_INITIALIZER; } while (0)

static inline void mutex_lock(struct mutex *lock)
{
#ifdef LOCK_DEBUG
	down_write(&lock->sem);
#endif
}
#define mutex_lock_nested(lock, sub) mutex_lock(lock)
static inline void mutex_unlock(struct mutex *lock)
{
#ifdef LOCK_DEBUG
	up_write(&lock->sem);
#endif
}
#endif /* !LIBKLIB_LOCKDEBUG_H */
