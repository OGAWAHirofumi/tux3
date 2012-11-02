/*
 * Iattr  Fork (Copy-On-Write of inode attributes)
 */

#include "tux3_fork.h"

TUX3_DEFINE_STATE_FNS(unsigned, iattr, IATTR_DIRTY,
		      IFLAGS_IATTR_BITS, IFLAGS_IATTR_SHIFT);

void tux3_iattrdirty(struct inode *inode)
{
}

static void tux3_iattr_clear_dirty(struct inode *inode)
{
}

void tux3_iattr_read_and_clear(struct inode *inode)
{
}
