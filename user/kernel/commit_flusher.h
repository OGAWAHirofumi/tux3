#ifndef TUX3_COMMIT_FLUSHER_H
#define TUX3_COMMIT_FLUSHER_H

/* FIXME: Remove this file after implement of flusher interface */

#if TUX3_FLUSHER == TUX3_FLUSHER_ASYNC_HACK
/* Hack for BDI_CAP_NO_WRITEBACK */
void tux3_set_mapping_bdi(struct inode *inode);
#else
static inline void tux3_set_mapping_bdi(struct inode *inode) { }
#endif

int tux3_init_flusher(struct sb *sb);
void tux3_exit_flusher(struct sb *sb);

#endif /* !TUX3_COMMIT_FLUSHER_H */
