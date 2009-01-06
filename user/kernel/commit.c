/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

#ifndef trace
#define trace trace_off
#endif

int unpack_sb(struct sb *sb, struct disksuper *super, int silent)
{
	u64 iroot = from_be_u64(super->iroot);
	if (memcmp(super->magic, (char[])SB_MAGIC, sizeof(super->magic))) {
		if (!silent)
			printf("invalid superblock [%Lx]\n",
			       (L)from_be_u64(*(be_u64 *)super->magic));
		return -EINVAL;
	}

//	sb->rootbuf;
	sb->blockbits = from_be_u16(super->blockbits);
	sb->blocksize = 1 << sb->blockbits;
	sb->blockmask = (1 << sb->blockbits) - 1;
	/* FIXME: those should be initialized based on blocksize. */
	sb->entries_per_node = 20;
	sb->max_inodes_per_block = 64;
//	sb->version;
	sb->atomref_base = 1 << (40 - sb->blockbits); // see xattr.c
	sb->unatom_base = sb->atomref_base + (1 << (34 - sb->blockbits));
	sb->volblocks = from_be_u64(super->volblocks);
	sb->freeblocks = from_be_u64(super->freeblocks);
	sb->nextalloc = from_be_u64(super->nextalloc);
	sb->atomgen = from_be_u32(super->atomgen);
	sb->freeatom = from_be_u32(super->freeatom);
	sb->dictsize = from_be_u64(super->dictsize);

	init_btree(&sb->itable, sb, unpack_root(iroot), &itable_ops);

	return 0;
}

void pack_sb(struct sb *sb, struct disksuper *super)
{
	super->blockbits = to_be_u16(sb->blockbits);
	super->volblocks = to_be_u64(sb->volblocks);
	super->freeblocks = to_be_u64(sb->freeblocks); // probably does not belong here
	super->nextalloc = to_be_u64(sb->nextalloc); // probably does not belong here
	super->atomgen = to_be_u32(sb->atomgen); // probably does not belong here
	super->freeatom = to_be_u32(sb->freeatom); // probably does not belong here
	super->dictsize = to_be_u64(sb->dictsize); // probably does not belong here
	super->iroot = to_be_u64(pack_root(&sb->itable.root));
}

struct logblock { be_u16 magic, bytes; be_u64 prevlog; unsigned char data[]; };

enum { LOG_ALLOC, LOG_FREE, LOG_UPDATE };

struct commit_entry { be_u64 previous; };

void log_next(struct sb *sb)
{
	sb->logbuf = blockget(mapping(sb->logmap), sb->lognext++);
	sb->logpos = bufdata(sb->logbuf) + sizeof(struct logblock);
	sb->logtop = bufdata(sb->logbuf) + sb->blocksize;
}

void log_finish(struct sb *sb)
{
	struct logblock *log = bufdata(sb->logbuf);
	assert(sb->logtop >= sb->logpos);
	log->bytes = to_be_u16(sb->logpos - log->data);
	memset(sb->logpos, 0, sb->logtop - sb->logpos);
	brelse(sb->logbuf);
	sb->logbuf = NULL;
}

void *log_begin(struct sb *sb, unsigned bytes)
{
	mutex_lock(&sb->loglock);
	if (sb->logpos + bytes > sb->logtop) {
		if (sb->logbuf)
			log_finish(sb);
		log_next(sb);
		*(struct logblock *)bufdata(sb->logbuf) = (struct logblock){
			.magic = to_be_u16(0xc0de) };
	}
	return sb->logpos;
}

void log_end(struct sb *sb, void *pos)
{
	sb->logpos = pos;
	mutex_unlock(&sb->loglock);
}

void log_alloc(struct sb *sb, block_t block, unsigned count, unsigned alloc)
{
	unsigned char *data = log_begin(sb, 8);
	*data++ = alloc ? LOG_ALLOC : LOG_FREE;
	*data++ = count;
	log_end(sb, encode48(data, block));
}

void log_update(struct sb *sb, block_t child, block_t parent, tuxkey_t key)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_UPDATE;
	data = encode48(data, child);
	data = encode48(data, parent);
	log_end(sb, encode48(data, key));
}
