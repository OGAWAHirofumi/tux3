#ifndef TUX3_ILEAF_H
#define TUX3_ILEAF_H

struct ileaf_attr_ops {
	be_u16 magic;			/* magic number to set to ileaf */
	int (*encoded_size)(struct btree *btree, void *data);
	void (*encode)(struct btree *btree, void *data, void *attrs, int size);
	int (*decode)(struct btree *btree, void *data, void *attrs, int size);
};

struct ileaf_req {
	struct btree_key_range key;	/* inum and count */

	void *data;			/* attr data */
};

#endif /* !TUX3_ILEAF_H */
