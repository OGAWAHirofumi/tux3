#include "tux3.h"

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 12 };
	map_t *map = new_map(dev, NULL);
	init_buffers(dev, 1 << 20, 0);
	show_dirty_buffers(map);
	set_buffer_dirty(blockget(map, 1));
	show_dirty_buffers(map);
	printf("get %p\n", blockget(map, 0));
	printf("get %p\n", blockget(map, 1));
	printf("get %p\n", blockget(map, 2));
	printf("get %p\n", blockget(map, 1));
	show_dirty_buffers(map);
	exit(0);
}
