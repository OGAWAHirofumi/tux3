/*
 * Inode attributes.
 *
 * Copyright (c) 2008-2014 Daniel Phillips
 * Copyright (c) 2008-2014 OGAWA Hirofumi
 */

#include "tux3.h"
#include "ileaf.h"
#include "iattr.h"

/*
 * Variable size attribute format:
 *
 *    immediate data: kind+version:16, bytes:16, data[bytes]
 *    immediate xattr: kind+version:16, bytes:16, atom:16, data[bytes - 2]
 */

unsigned atsize[MAX_ATTRS] = {
	/* Fixed size attrs */
	[RDEV_ATTR] = 8,
	[MODE_OWNER_ATTR] = 12,
	[CTIME_SIZE_ATTR] = 16,
	[DATA_BTREE_ATTR] = 8,
	[LINK_COUNT_ATTR] = 4,
	[MTIME_ATTR] = 8,
	/* Variable size (extended) attrs */
	[IDATA_ATTR] = 2,
	[XATTR_ATTR] = 4,
};

/*
 * Tux3 times are nanosecond from base FS time (for now, same with unix epoch).
 * It is not clear whether the saved space is worth the lower precision.
 */

static inline struct timespec spectime(const s64 time)
{
	return ns_to_timespec(time);
}

static inline s64 tuxtime(const struct timespec ts)
{
	return timespec_to_ns(&ts);
}

static unsigned encode_asize(unsigned bits)
{
	unsigned need = 0;

	for (int kind = 0; kind < VAR_ATTRS; kind++)
		if ((bits & (1 << kind)))
			need += atsize[kind] + 2;
	return need;
}

/* unused */
int attr_check(void *attrs, unsigned size)
{
	void *limit = attrs + size;
	unsigned head;

	while (attrs < limit - 1)
	{
		attrs = decode16(attrs, &head);
		unsigned kind = head >> 12;
		if (kind >= MAX_ATTRS)
			return 0;
		if (attrs + atsize[kind] > limit)
			return 0;
		attrs += atsize[kind];
	}
	return 1;
}

void dump_attrs(struct inode *inode)
{
	//tux3_dbg("present = %x", inode->present);
	struct tux3_inode *tuxnode = tux_inode(inode);

	for (int kind = 0; kind < MAX_ATTRS; kind++) {
		if (!(tux_inode(inode)->present & (1 << kind)))
			continue;
		switch (kind) {
		case RDEV_ATTR:
			__tux3_dbg("rdev %x:%x ", MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
			break;
		case MODE_OWNER_ATTR:
			__tux3_dbg("mode %07ho uid %x gid %x ", inode->i_mode, i_uid_read(inode), i_gid_read(inode));
			break;
		case CTIME_SIZE_ATTR:
			__tux3_dbg("ctime %Lx size %Lx ", tuxtime(inode->i_ctime), (s64)inode->i_size);
			break;
		case LINK_COUNT_ATTR:
			__tux3_dbg("links %u ", inode->i_nlink);
			break;
		case MTIME_ATTR:
			__tux3_dbg("mtime %Lx ", tuxtime(inode->i_mtime));
			break;
		case XATTR_ATTR:
			__tux3_dbg("xattr(s) ");
			break;
		default:
			__tux3_dbg("<%i>? ", kind);
			break;
		}
	}
	if (has_root(&tuxnode->btree))
		__tux3_dbg("root %Lx:%u ", tuxnode->btree.root.block,
			   tuxnode->btree.root.depth);
	__tux3_dbg("\n");
}

void *encode_kind(void *attrs, unsigned kind, unsigned version)
{
	return encode16(attrs, (kind << 12) | version);
}

static void *encode_attrs(struct btree *btree, void *data, void *attrs,
			  unsigned size)
{
	struct sb *sb = btree->sb;
	struct iattr_req_data *iattr_data = data;
	struct tux3_iattr_data *idata = iattr_data->idata;
	struct btree *attr_btree = iattr_data->btree;
	void *limit = attrs + size - 3;

	for (int kind = 0; kind < VAR_ATTRS; kind++) {
		if (!(idata->present & (1 << kind)))
			continue;
		if (attrs >= limit)
			break;
		attrs = encode_kind(attrs, kind, sb->version);
		switch (kind) {
		case RDEV_ATTR:
			attrs = encode64(attrs, huge_encode_dev(idata->i_rdev));
			break;
		case MODE_OWNER_ATTR:
			/* FIXME: i_mode is enough with 16bits */
			attrs = encode32(attrs, idata->i_mode);
			attrs = encode32(attrs, idata->i_uid);
			attrs = encode32(attrs, idata->i_gid);
			break;
		case CTIME_SIZE_ATTR:
			attrs = encode64(attrs, tuxtime(idata->i_ctime));
			attrs = encode64(attrs, idata->i_size);
			break;
		case DATA_BTREE_ATTR:
			attrs = encode64(attrs, pack_root(&attr_btree->root));
			break;
		case LINK_COUNT_ATTR:
			attrs = encode32(attrs, idata->i_nlink);
			break;
		case MTIME_ATTR:
			attrs = encode64(attrs, tuxtime(idata->i_mtime));
			break;
		}
	}
	return attrs;
}

void *decode_kind(void *attrs, unsigned *kind, unsigned *version)
{
	unsigned head;
	attrs = decode16(attrs, &head);
	*version = head & 0xfff;
	*kind = head >> 12;
	return attrs;
}

static void *decode_attrs(struct inode *inode, void *attrs, unsigned size)
{
	trace_off("decode %u attr bytes", size);
	struct sb *sb = tux_sb(inode->i_sb);
	struct tux3_inode *tuxnode = tux_inode(inode);
	struct root btree_root = no_root;
	void *limit = attrs + size;
	u64 v64;
	u32 v32;

	while (attrs < limit - 1) {
		unsigned version, kind;
		attrs = decode_kind(attrs, &kind, &version);
		if (version != sb->version) {
			attrs += atsize[kind];
			continue;
		}
		switch (kind) {
		case RDEV_ATTR:
			attrs = decode64(attrs, &v64);
			/* vfs, trying to be helpful, will rewrite the field */
			inode->i_rdev = huge_decode_dev(v64);
			break;
		case MODE_OWNER_ATTR:
			attrs = decode32(attrs, &v32);
			inode->i_mode = v32;
			attrs = decode32(attrs, &v32);
			i_uid_write(inode, v32);
			attrs = decode32(attrs, &v32);
			i_gid_write(inode, v32);
			break;
		case CTIME_SIZE_ATTR:
			attrs = decode64(attrs, &v64);
			inode->i_ctime = spectime(v64);
			attrs = decode64(attrs, &v64);
			inode->i_size = v64;
			break;
		case DATA_BTREE_ATTR:
			attrs = decode64(attrs, &v64);
			btree_root = unpack_root(v64);
			goto skip_present;
			break;
		case LINK_COUNT_ATTR: {
			unsigned nlink;
			attrs = decode32(attrs, &nlink);
			set_nlink(inode, nlink);
			break;
		}
		case MTIME_ATTR:
			attrs = decode64(attrs, &v64);
			inode->i_mtime = spectime(v64);
			break;
		case XATTR_ATTR:
			attrs = decode_xattr(inode, attrs);
			break;
		default:
			return NULL;
		}

		tuxnode->present |= 1 << kind;
	skip_present:
		;
	}

	/* We don't use ->present for btree root */
	init_btree(&tuxnode->btree, sb, btree_root, &dtree_ops);

	return attrs;
}

static int iattr_encoded_size(struct btree *btree, void *data)
{
	struct iattr_req_data *iattr_data = data;
	struct inode *inode = iattr_data->inode;

	return encode_asize(iattr_data->idata->present) + encode_xsize(inode);
}

static void iattr_encode(struct btree *btree, void *data, void *attrs, int size)
{
	struct iattr_req_data *iattr_data = data;
	struct inode *inode = iattr_data->inode;
	void *attr;

	attr = encode_attrs(btree, data, attrs, size);
	attr = encode_xattrs(inode, attr, attrs + size - attr);
	assert(attr == attrs + size);
}

static int iattr_decode(struct btree *btree, void *data, void *attrs, int size)
{
	struct inode *inode = data;
	unsigned xsize;

	xsize = decode_xsize(inode, attrs, size);
	if (xsize) {
		int err = new_xcache(inode, xsize);
		if (err)
			return err;
	}

	decode_attrs(inode, attrs, size); // error???
	if (tux3_trace)
		dump_attrs(inode);
	if (tux_inode(inode)->xcache)
		xcache_dump(inode);

	return 0;
}

struct ileaf_attr_ops iattr_ops = {
	.magic		= cpu_to_be16(TUX3_MAGIC_ILEAF),
	.encoded_size	= iattr_encoded_size,
	.encode		= iattr_encode,
	.decode		= iattr_decode,
};
