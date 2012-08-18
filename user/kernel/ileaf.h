#ifndef TUX3_ILEAF_H
#define TUX3_ILEAF_H

struct ileaf_attr_ops {
	int (*encoded_size)(struct btree *btree, void *data);
	void (*encode)(struct btree *btree, void *data, void *attrs, int size);
};

struct ileaf_req {
	struct btree_key_range key;	/* inum and count */

	void *data;			/* attr data */
};

#endif /* !TUX3_ILEAF_H */
