/*
 * Block Fork (Copy-On-Write of logically addressed block)
 */

/*
 * For now, there is no concurrent reader in the userland, so we can
 * free the buffer at I/O completion.
 */
void free_forked_buffers(struct sb *sb, int umount)
{
}

struct buffer_head *blockdirty(struct buffer_head *buffer, unsigned newdelta)
{
#ifndef ATOMIC
	return buffer;
#endif
	assert(buffer->state < BUFFER_STATES);

	buftrace("---- before: fork buffer %p ----", buffer);
	if (buffer_dirty(buffer)) {
		if (buffer_can_modify(buffer, newdelta))
			return buffer;

		/* Buffer can't modify already, we have to fork buffer */
		buftrace("---- fork buffer %p ----", buffer);
		struct buffer_head *clone = new_buffer(buffer->map);
		if (IS_ERR(clone))
			return clone;
		/* Create the cloned buffer */
		memcpy(bufdata(clone), bufdata(buffer), bufsize(buffer));
		clone->index = buffer->index;
		/* Replace the buffer by cloned buffer. */
		remove_buffer_hash(buffer);
		insert_buffer_hash(clone);

		/*
		 * The refcount of buffer is used for backend. So, the
		 * backend has to free this buffer (blockput(buffer))
		 */
		buffer = clone;
	}

	tux3_set_buffer_dirty(buffer, newdelta);
	__mark_inode_dirty(buffer_inode(buffer), I_DIRTY_PAGES);

	return buffer;
}
