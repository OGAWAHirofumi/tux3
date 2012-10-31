#ifndef TUX3_IATTR_H
#define TUX3_IATTR_H

enum atkind {
	/* Fixed size attrs */
	RDEV_ATTR	= 0,
	MODE_OWNER_ATTR	= 1,
	DATA_BTREE_ATTR	= 2,
	CTIME_SIZE_ATTR	= 3,
	LINK_COUNT_ATTR	= 4,
	MTIME_ATTR	= 5,
	/* i_blocks	= 6 */
	/* i_generation	= 7 */
	/* i_version	= 8 */
	/* i_flag	= 9 */
	RESERVED1_ATTR	= 10,
	VAR_ATTRS,
	/* Variable size (extended) attrs */
	IDATA_ATTR	= 11,
	XATTR_ATTR	= 12,
	/* acl		= 13 */
	/* allocation hint = 14 */
	RESERVED2_ATTR	= 15,
	MAX_ATTRS,
};

enum atbit {
	/* Fixed size attrs */
	RDEV_BIT	= 1 << RDEV_ATTR,
	MODE_OWNER_BIT	= 1 << MODE_OWNER_ATTR,
	CTIME_SIZE_BIT	= 1 << CTIME_SIZE_ATTR,
	DATA_BTREE_BIT	= 1 << DATA_BTREE_ATTR,
	LINK_COUNT_BIT	= 1 << LINK_COUNT_ATTR,
	MTIME_BIT	= 1 << MTIME_ATTR,
	/* Variable size (extended) attrs */
	IDATA_BIT	= 1 << IDATA_ATTR,
	XATTR_BIT	= 1 << XATTR_ATTR,
};

extern unsigned atsize[MAX_ATTRS];

struct iattr_req_data {
	struct inode_delta_dirty *i_ddc;	/* inode attributes */
	struct root *root;			/* inode btree root */
	struct inode *inode;			/* extended attributes */
};
#endif /* !TUX3_IATTR_H */
