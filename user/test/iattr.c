/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "tux3.h"

enum { MTIME_SIZE_ATTR = 8, DATA_BTREE_ATTR = 9 };

struct size_mtime_attr { u64 kind:4, size:60, version:10, mtime:54; };
struct data_btree_attr { u64 kind:4; struct diskroot root; };

#ifndef main
int main(int argc, char *argv[])
{
	return 0;
}
#endif

