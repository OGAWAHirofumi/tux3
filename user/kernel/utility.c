/* Copyright (c) 2008 Daniel Phillips <phillips@phunq.net>, GPL v2 */

#include <linux/kernel.h>
#include <linux/bio.h>

int vecio(int rw, struct block_device *dev, loff_t offset,
	bio_end_io_t endio, void *data, unsigned vecs, struct bio_vec *vec)
{
	struct bio *bio = bio_alloc(GFP_KERNEL, vecs);
	if (!bio)
		return -ENOMEM;
	bio->bi_bdev = dev;
	bio->bi_sector = offset >> 9;
	bio->bi_end_io = endio;
	bio->bi_private = data;
	while (vecs--) {
		bio->bi_io_vec[bio->bi_vcnt] = *vec++;
		bio->bi_size += bio->bi_io_vec[bio->bi_vcnt++].bv_len;
	}
	submit_bio(rw, bio);
	return 0;
}

struct biosync { wait_queue_head_t wait; int done, err; };

static void biosync_endio(struct bio *bio, int err)
{
	struct biosync *sync = bio->bi_private;
	bio_put(bio);
	sync->err = err;
	sync->done = 1;
	wake_up(&sync->wait);
}

int syncio(int rw, struct block_device *dev, loff_t offset, unsigned vecs, struct bio_vec *vec)
{
	struct biosync sync = { .wait = __WAIT_QUEUE_HEAD_INITIALIZER(sync.wait) };
	if (!(sync.err = vecio(rw, dev, offset, biosync_endio, &sync, vecs, vec)))
		wait_event(sync.wait, sync.done);
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
