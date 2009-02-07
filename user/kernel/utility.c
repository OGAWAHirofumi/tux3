/* Copyright (c) 2008 Daniel Phillips <phillips@phunq.net>, GPL v2 */

#include <linux/kernel.h>
#include <linux/bio.h>

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

void hexdump(void *data, unsigned size)
{
	while (size) {
		unsigned char *p;
		int w = 16, n = size < w? size: w, pad = w - n;
		printk("%p:  ", data);
		for (p = data; p < (unsigned char *)data + n;)
			printk("%02hx ", *p++);
		printk("%*.s  \"", pad*3, "");
		for (p = data; p < (unsigned char *)data + n;) {
			int c = *p++;
			printk("%c", c < ' ' || c > 127 ? '.' : c);
		}
		printk("\"\n");
		data += w;
		size -= n;
	}
}
