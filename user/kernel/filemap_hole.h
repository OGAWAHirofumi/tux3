#ifndef TUX3_FILEMAP_HOLE_H
#define TUX3_FILEMAP_HOLE_H

int __init tux3_init_hole_cache(void);
void tux3_destroy_hole_cache(void);
int tux3_flush_hole(struct inode *inode, unsigned delta);
int tux3_add_truncate_hole(struct inode *inode, loff_t newsize);
void tux3_clear_hole(struct inode *inode);

#endif /* !TUX3_FILEMAP_HOLE_H */
