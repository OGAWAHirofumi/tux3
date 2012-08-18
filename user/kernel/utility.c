/* Copyright (c) 2008 Daniel Phillips <phillips@phunq.net>, GPL v2 */

#ifdef __KERNEL__
#include "tux3.h"

int vecio(int rw, struct block_device *dev, loff_t offset, unsigned vecs, struct bio_vec *vec,
	bio_end_io_t endio, void *info)
{
	BUG_ON(vecs > bio_get_nr_vecs(dev));
	struct bio *bio = bio_alloc(GFP_NOIO, vecs);
	if (!bio)
		return -ENOMEM;
	bio->bi_bdev = dev;
	bio->bi_sector = offset >> 9;
	bio->bi_end_io = endio;
	bio->bi_private = info;
	bio->bi_vcnt = vecs;
	memcpy(bio->bi_io_vec, vec, sizeof(*vec) * vecs);
	while (vecs--)
		bio->bi_size += bio->bi_io_vec[vecs].bv_len;
	submit_bio(rw, bio);
	return 0;
}

struct biosync { struct completion done; int err; };

static void biosync_endio(struct bio *bio, int err)
{
	struct biosync *sync = bio->bi_private;
	bio_put(bio);
	sync->err = err;
	complete(&sync->done);
}

int syncio(int rw, struct block_device *dev, loff_t offset, unsigned vecs, struct bio_vec *vec)
{
	struct biosync sync = { .done = COMPLETION_INITIALIZER_ONSTACK(sync.done) };
	if (!(sync.err = vecio(rw, dev, offset, vecs, vec, biosync_endio, &sync)))
		wait_for_completion(&sync.done);
	return sync.err;
}

int devio(int rw, struct block_device *dev, loff_t offset, void *data, unsigned len)
{
	return syncio(rw, dev, offset, 1, &(struct bio_vec){
		.bv_page = virt_to_page(data),
		.bv_offset = offset_in_page(data),
		.bv_len = len });
}

int blockio(int rw, struct buffer_head *buffer, block_t block)
{
	struct sb *sb = tux_sb(buffer_inode(buffer)->i_sb);
	struct bio_vec vec = {
		.bv_page	= buffer->b_page,
		.bv_offset	= bh_offset(buffer),
		.bv_len		= sb->blocksize,
	};

	return syncio(rw, sb_dev(sb), block << sb->blockbits, 1, &vec);
}

/*
 * bufvec based I/O.  This takes the bufvec has contiguous range, and
 * will submit the count of buffers to block (physical address).
 *
 * If there was I/O error, it would be handled in ->bi_end_bio()
 * completion.
 */
int blockio_vec(int rw, struct bufvec *bufvec, block_t block, unsigned count)
{
	return bufvec_io(rw, bufvec, block, count);
}

void hexdump(void *data, unsigned size)
{
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 1, data, size, 1);
}
#endif /* !__KERNEL__ */

/* Bitmap operations... try to use linux/lib/bitmap.c */

void set_bits(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		bitmap[loff] |= lmask & rmask;
		return;
	}
	bitmap[loff] |= lmask;
	memset(bitmap + loff + 1, -1, roff - loff - 1);
	if (rmask)
		bitmap[roff] |= rmask;
}

void clear_bits(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff; // little endian!!!
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff; // little endian!!!
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		bitmap[loff] &= ~lmask | ~rmask;
		return;
	}
	bitmap[loff] &= ~lmask;
	memset(bitmap + loff + 1, 0, roff - loff - 1);
	if (rmask)
		bitmap[roff] &= ~rmask;
}

int all_set(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff;	/* little endian!!! */
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff;	/* little endian!!! */
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		unsigned mask = lmask & rmask;
		return (bitmap[loff] & mask) == mask;
	}
	for (unsigned i = loff + 1; i < roff; i++)
		if (bitmap[i] != 0xff)
			return 0;
	return	(bitmap[loff] & lmask) == lmask &&
		(!rmask || (bitmap[roff] & rmask) == rmask);
}

int all_clear(u8 *bitmap, unsigned start, unsigned count)
{
	unsigned limit = start + count;
	unsigned lmask = (-1 << (start & 7)) & 0xff;	/* little endian!!! */
	unsigned rmask = ~(-1 << (limit & 7)) & 0xff;	/* little endian!!! */
	unsigned loff = start >> 3, roff = limit >> 3;

	if (loff == roff) {
		unsigned mask = lmask & rmask;
		return !(bitmap[loff] & mask);
	}
	for (unsigned i = loff + 1; i < roff; i++)
		if (bitmap[i])
			return 0;
	return	!(bitmap[loff] & lmask) &&
		(!rmask || !(bitmap[roff] & rmask));
}

int bytebits(u8 c)
{
	unsigned count = 0;

	for (; c; c >>= 1)
		count += c & 1;
	return count;
}
