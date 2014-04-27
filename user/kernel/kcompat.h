#ifndef TUX3_KCOMPAT_H
#define TUX3_KCOMPAT_H

#ifdef __KERNEL__

/*
 * Temporary support for older kernel
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define bio_bi_sector(x)	(x)->bi_sector
#define bio_bi_size(x)		(x)->bi_size
#else
#define bio_bi_sector(x)	(x)->bi_iter.bi_sector
#define bio_bi_size(x)		(x)->bi_iter.bi_size
#endif

#endif /* !__KERNEL__ */
#endif /* !TUX3_KCOMPAT_H */
