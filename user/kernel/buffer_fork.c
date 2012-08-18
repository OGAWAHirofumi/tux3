/*
 * Block Fork (Copy-On-Write of logically addressed block)
 */

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
	/* FIXME: need to implement block fork */
	mark_buffer_dirty_atomic(buffer);
	return buffer;
}
