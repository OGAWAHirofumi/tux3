/*
 * Writeback for inodes
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

void tux3_mark_buffer_dirty(struct buffer_head *buffer)
{
}

void tux3_mark_buffer_rollup(struct buffer_head *buffer)
{
}

int tux3_flush_inode(struct inode *inode, unsigned delta)
{
	return 0;
}

int tux3_flush_inodes(struct sb *sb, unsigned delta)
{
	return 0;
}
