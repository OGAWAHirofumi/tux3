#ifndef TUX3_KCOMPAT_H
#define TUX3_KCOMPAT_H

#ifdef __KERNEL__

/*
 * Temporary support for older kernel
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static inline struct inode *file_inode(struct file *file)
{
	return file->f_dentry->d_inode;
}

#define MODULE_ALIAS_FS(x)
#endif

#endif /* !__KERNEL__ */
#endif /* !TUX3_KCOMPAT_H */
