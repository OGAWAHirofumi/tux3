#include "tux3user.h"
#include "test.h"

#define NR_BUF		100

static void test01(void)
{
	struct dev *dev = &(struct dev){ .bits = 12 };

	/* This expect buffer is never reclaimed */
	init_buffers(dev, NR_BUF << dev->bits, 1);

	map_t *map1 = new_map(dev, NULL);
	map_t *map2 = new_map(dev, NULL);

	struct buffer_head *map1_bufs[NR_BUF], *map2_bufs[NR_BUF];

	/* There is no buffer yet, peekblk should return NULL */
	for (int i = 0; i < ARRAY_SIZE(map1_bufs); i++) {
		map1_bufs[i] = peekblk(map1, i);
		test_assert(map1_bufs[i] == NULL);
	}
	/* Fill buffers */
	for (int i = 0; i < ARRAY_SIZE(map1_bufs); i++) {
		map1_bufs[i] = blockget(map1, i);
		test_assert(map1_bufs[i]);
		test_assert(map1_bufs[i]->index == i);
		blockput(map1_bufs[i]);
	}
	/* There is buffer, peekblk should return buffer */
	for (int i = 0; i < ARRAY_SIZE(map1_bufs); i++) {
		map1_bufs[i] = peekblk(map1, i);
		test_assert(map1_bufs[i]);
		test_assert(map1_bufs[i]->index == i);
		blockput(map1_bufs[i]);
	}

	struct buffer_head *buf;

	/* Test blockget() gets expected buffer */
	int index[] = { 0, 1, 2, 1, 5, 6, };
	for (int i = 0; i < ARRAY_SIZE(index); i++) {
		buf = blockget(map1, index[i]);
		test_assert(buf == map1_bufs[index[i]]);
		test_assert(buf->index == index[i]);
		blockput(buf);
	}

	/* Test dirty */
	buf = blockget(map1, 0);
	test_assert(buf == map1_bufs[0]);
	set_buffer_dirty(buf);
	test_assert(buffer_dirty(buf));
	blockput(buf);

	/* This should reclaim map1_bufs except dirty */
	int last = ARRAY_SIZE(map2_bufs) - 1;
	for (int i = 0; i < ARRAY_SIZE(map2_bufs); i++) {
		map2_bufs[i] = blockget(map2, i);
		if (i == last)
			test_assert(map2_bufs[i] == NULL);
		else {
			test_assert(map2_bufs[i]);
			test_assert(map2_bufs[i]->index == i);
		}
	}
	/* Clear dirty and reclaim again */
	buf = blockget(map1, 0);
	blockput_free(buf);

	map2_bufs[last] = blockget(map2, last);
	test_assert(map2_bufs[last]);

	/* There is buffer, peekblk should return buffer */
	for (int i = 0; i < ARRAY_SIZE(map2_bufs); i++) {
		buf = peekblk(map2, i);
		test_assert(buf);
		test_assert(buf->index == i);
		blockput(buf);
	}

	/* Set dirty, invalidate_buffers should clear it */
	set_buffer_dirty(map2_bufs[last]);
	for (int i = 0; i < ARRAY_SIZE(map2_bufs); i++)
		blockput(map2_bufs[i]);
	invalidate_buffers(map2);

	free_map(map1);
	free_map(map2);
}

int main(int argc, char *argv[])
{
	test_init(argv[0]);

	if (test_start("test01"))
		test01();
	test_end();

	return test_failures();
}
