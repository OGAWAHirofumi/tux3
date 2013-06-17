#ifndef TUX3_COMMIT_FLUSHER_H
#define TUX3_COMMIT_FLUSHER_H

/* FIXME: Remove this file after implement of flusher interface */

#if TUX3_FLUSHER == TUX3_FLUSHER_ASYNC_HACK
/* Hack for BDI_CAP_NO_WRITEBACK */
void tux3_accout_set_writeback(struct page *page);
void tux3_accout_clear_writeback(struct page *page);
void tux3_set_mapping_bdi(struct inode *inode);
void tux3_start_periodical_flusher(struct sb *sb);
#else
static inline void tux3_accout_set_writeback(struct page *page) { }
static inline void tux3_accout_clear_writeback(struct page *page) { }
static inline void tux3_set_mapping_bdi(struct inode *inode) { }
static inline void tux3_start_periodical_flusher(struct sb *sb) { }
#endif

int tux3_init_flusher(struct sb *sb);
void tux3_exit_flusher(struct sb *sb);
int tux3_setup_flusher(struct sb *sb);
void tux3_cleanup_flusher(struct sb *sb);

#endif /* !TUX3_COMMIT_FLUSHER_H */
