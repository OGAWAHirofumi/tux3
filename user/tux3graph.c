/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 *
 * $ tux3graph [-v] volname
 * $ dot -Tpng -O volname.dot
 * $ viewer volname.dot.png
 */

#define include_inode_c
#include "inode.c"
#include <popt.h>

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

static int fls(uint32_t v)
{
	uint32_t mask;
	int bit = 0;
	for (bit = 32, mask = 1 << 31; bit; mask >>= 1, bit--)
		if ((v & mask))
			break;
	return bit;
}

static const char *dtree_names[] = {
	[TUX_BITMAP_INO]	= "bitmap",
	[TUX_VTABLE_INO]	= "vtable",
	[TUX_ATABLE_INO]	= "atable",
	[TUX_ROOTDIR_INO]	= "rootdir",
};

static int verbose;
#define DRAWN_DTREE	(1 << 0)
#define DRAWN_DLEAF	(1 << 1)
#define DRAWN_ILEAF	(1 << 2)
static int drawn;

struct graph_info {
	FILE *f;
	const char *bname;	/* btree name */
	const char *lname;	/* leaf name */
};

typedef void (*draw_leaf_t)(struct graph_info *, BTREE, struct buffer_head *);

static void draw_sb(struct graph_info *gi, struct sb *sb)
{
	struct disksuper *txsb = &sb->super;

	fprintf(gi->f,
		"tux3_sb [\n"
		"label = \"{ [disksuper] (blocknr %llu)"
		" | magic %.4s, 0x%02x, 0x%02x, 0x%02x, 0x%02x"
		" | birthdate %llu | flags 0x%016llx"
		" | <iroot0> iroot 0x%016llx (depth %u, block %llu)"
		" | aroot %llu | blockbits %u (size %u) | volblocks %llu"
		" | freeblocks %llu | nextalloc %llu"
		" | freeatom %u | atomgen %u }\"\n"
		"shape = record\n"
		"];\n",
		(L)SB_LOC >> sb->blockbits,
		txsb->magic,
		(u8)txsb->magic[4], (u8)txsb->magic[5],
		(u8)txsb->magic[6], (u8)txsb->magic[7],
		(L)from_be_u64(txsb->birthdate),
		(L)from_be_u64(txsb->flags), (L)from_be_u64(txsb->iroot),
		sb->itable.root.depth, (L)sb->itable.root.block,
		(L)from_be_u64(txsb->aroot), sb->blockbits, sb->blocksize,
		(L)from_be_u64(txsb->volblocks),
		(L)from_be_u64(txsb->freeblocks),
		(L)from_be_u64(txsb->nextalloc),
		from_be_u32(txsb->freeatom), from_be_u32(txsb->atomgen));

	fprintf(gi->f, "tux3_sb:iroot0:e -> %s_bnode_%llu:n;\n",
		gi->bname, (L)sb->itable.root.block);
}

static void draw_bnode(struct graph_info *gi, int depth, int level,
		       struct buffer_head *buffer)
{
	struct bnode *bnode = buffer->data;
	block_t blocknr = buffer->index;
	struct index_entry *index = bnode->entries;
	int n;

	fprintf(gi->f,
		"%s_bnode_%llu [\n"
		"label = \"{ <bnode0> [bnode] | count %u |",
		gi->bname, (L)blocknr, bcount(bnode));
	for (n = 0; n < bcount(bnode); n++) {
		fprintf(gi->f,
			" %c <f%u> key %llu, block %lld",
			n ? '|' : '{', n,
			(L)from_be_u64(index[n].key), (L)from_be_u64(index[n].block));
	}
	fprintf(gi->f,
		" }}\"\n"
		"shape = record\n"
		"];\n");

	if (level == depth - 1) {
		for (n = 0; n < bcount(bnode); n++) {
			fprintf(gi->f,
				"%s_bnode_%llu:f%u -> %s_%llu:%s0;\n",
				gi->bname, (L)blocknr, n,
				gi->lname, (L)from_be_u64(index[n].block),
				gi->lname);
		}
	} else {
		for (n = 0; n < bcount(bnode); n++) {
			fprintf(gi->f,
				"%s_bnode_%llu:f%u -> %s_bnode_%llu:bnode0;\n",
				gi->bname, (L)blocknr, n,
				gi->bname, (L)from_be_u64(index[n].block));
		}
	}
}

static void draw_cursor(struct graph_info *gi, BTREE, struct cursor cursor[])
{
	int level;
	for (level = 0; level < btree->root.depth; level++)
		draw_bnode(gi, btree->root.depth, level, cursor[level].buffer);
}

static int draw_advance(struct graph_info *gi, struct map *map,
			struct cursor cursor[], int depth)
{
	int level = depth;
	struct buffer_head *buffer = cursor[level].buffer;
	struct bnode *node;
	do {
		brelse(buffer);
		if (!level)
			return 0;
		node = (buffer = cursor[--level].buffer)->data;
	} while (level_finished(cursor, level));
	do {
		if (!(buffer = blockread(map, from_be_u64(cursor[level].next++->block))))
			goto eek;
		cursor[++level] = (struct cursor){
			.buffer = buffer,
			.next = ((struct bnode *)buffer->data)->entries
		};
		if (level < depth)
			draw_bnode(gi, depth, level, buffer);
	} while (level < depth);
	return 1;
eek:
	release_cursor(cursor, level);
	return -EIO;
}

static void draw_tree(struct graph_info *gi, BTREE, draw_leaf_t draw_leaf)
{
	struct cursor cursor[30]; // check for overflow!!!
	struct buffer_head *buffer;

	if (probe(btree, 0, cursor))
		error("tell me why!!!");

	draw_cursor(gi, btree, cursor);

	do {
		buffer = cursor[btree->root.depth].buffer;
		draw_leaf(gi, btree, buffer);
	} while (draw_advance(gi, buffer->map, cursor, btree->root.depth));
}

static inline struct group *dleaf_groups_ptr(BTREE, struct dleaf *dleaf)
{
	return (void *)dleaf + btree->sb->blocksize;
}

static inline struct group *dleaf_group_ptr(struct group *groups, int gr)
{
	return groups - (gr + 1);
}

static inline struct entry *dleaf_entries(struct dleaf *leaf, struct group *groups, int gr)
{
	struct entry *entries = (struct entry *)(groups - dleaf_groups(leaf));
	for (int i = 0; i < gr; i++)
		entries -= group_count(dleaf_group_ptr(groups, i));
	return entries;
}

static inline struct entry *dleaf_entry(struct entry *entries, int ent)
{
	return entries - (ent + 1);
}

static inline int dleaf_extent_count(struct entry *entries, int ent)
{
	int offset = ent ? entry_limit(dleaf_entry(entries, ent - 1)) : 0;
	return entry_limit(dleaf_entry(entries, ent)) - offset;
}

static inline struct extent *dleaf_extents(struct dleaf *dleaf,
					   struct group *groups,
					   int gr, int ent)
{
	struct extent *extents = dleaf->table;
	struct group *group;
	struct entry *entries;
	int i;

	for (i = 0; i < gr - 1; i++) {
		group = dleaf_group_ptr(groups, i);
		entries = dleaf_entries(dleaf, groups, i);
		extents += entry_limit(dleaf_entry(entries, group_count(group) - 1));
	}
	if (ent) {
		entries = dleaf_entries(dleaf, groups, i);
		extents += entry_limit(dleaf_entry(entries, ent - 1));
	}

	return extents;
}

static inline struct extent *dleaf_extent(struct extent *extents, int ex)
{
	return extents + ex;
}

static void draw_dleaf(struct graph_info *gi, BTREE, struct buffer_head *buffer)
{
	struct dleaf *leaf = buffer->data;
	block_t blocknr = buffer->index;
	struct group *groups = dleaf_groups_ptr(btree, leaf);
	struct extent *extents;
	int gr;

	if (!verbose && (drawn & DRAWN_DLEAF))
		return;
	drawn |= DRAWN_DLEAF;

	fprintf(gi->f,
		"%s_%llu [\n"
		"label = \"{ <%s0> [%s]"
		" | magic 0x%04x, free %u, used %u, groups %u",
		gi->lname, (L)blocknr,
		gi->lname, gi->lname,
		from_be_u16(leaf->magic), from_be_u16(leaf->free), from_be_u16(leaf->used), dleaf_groups(leaf));

	/* draw extents */
	for (gr = 0; gr < dleaf_groups(leaf); gr++) {
		struct group *group = dleaf_group_ptr(groups, gr);
		struct entry *entries = dleaf_entries(leaf, groups, gr);
		for (int ent = 0; ent < group_count(group); ent++) {
			int ex, ex_count = dleaf_extent_count(entries, ent);
			extents = dleaf_extents(leaf, groups, gr, ent);
			for (ex = 0; ex < ex_count; ex++) {
				fprintf(gi->f,
					" | <gr%uent%uex%u>"
					" version 0x%03x, count %u, block %llu "
					" (extent %u)",
					gr, ent, ex,
					extent_version(extents[ex]),
					extent_count(extents[ex]),
					(L)extent_block(extents[ex]),
					ex);
			}
		}
	}
	fprintf(gi->f,
		" | .....");

	/* draw entries */
	for (gr = dleaf_groups(leaf) - 1; gr >= 0; gr--) {
		struct group *group = dleaf_group_ptr(groups, gr);
		struct entry *entries = dleaf_entries(leaf, groups, gr);
		int ent;

		for (ent = group_count(group) - 1; ent >= 0; ent--) {
			struct entry *entry = dleaf_entry(entries, ent);

			fprintf(gi->f,
				" | <gr%uent%u> limit %u, keylo 0x%06x"
				" (entry %u, count %u, iblock %llu)",
				gr, ent, entry_limit(entry), entry_keylo(entry),
				ent, dleaf_extent_count(entries, ent),
				(L)get_index(group, entry));
		}
	}

	/* draw groups */
	for (gr = dleaf_groups(leaf) - 1; gr >= 0; gr--) {
		struct group *group = dleaf_group_ptr(groups, gr);

		fprintf(gi->f,
			" | <gr%u> count %u, keyhi 0x%06x (group %u)",
			gr, group_count(group), group_keyhi(group), gr);
	}

	fprintf(gi->f,
		" }\"\n"
		"shape = record\n"
		"];\n");

	for (gr = 0; gr < dleaf_groups(leaf); gr++) {
		struct group *group = dleaf_group_ptr(groups, gr);
		fprintf(gi->f,
			"%s_%llu:gr%u:w -> %s_%llu:gr%uent%u:w;\n",
			gi->lname, (L)blocknr, gr,
			gi->lname, (L)blocknr, gr, 0);
		for (int ent = 0; ent < group_count(group); ent++) {
			fprintf(gi->f,
				"%s_%llu:gr%uent%u:w"
				" -> %s_%llu:gr%uent%uex%u:w;\n",
				gi->lname, (L)blocknr, gr, ent,
				gi->lname, (L)blocknr, gr, ent, 0);
		}
	}
}

static inline be_u16 *ileaf_dict(BTREE, struct ileaf *ileaf)
{
	return (void *)ileaf + btree->sb->blocksize;
}

static inline u16 __ileaf_atdict(be_u16 *dict, int at)
{
	assert(at > 0);
	return from_be_u16(*(dict - at));
}

static inline u16 ileaf_attr_size(be_u16 *dict, int at)
{
	int size = __ileaf_atdict(dict, at + 1) - atdict(dict, at);
	assert(size >= 0);
	return size;
}

static void draw_ileaf(struct graph_info *gi, BTREE, struct buffer_head *buffer)
{
	struct ileaf *ileaf = buffer->data;
	block_t blocknr = buffer->index;
	be_u16 *dict = ileaf_dict(btree, ileaf);
	int at;

	if (!verbose && (drawn & DRAWN_ILEAF))
		return;
	drawn |= DRAWN_ILEAF;

	fprintf(gi->f,
		"%s_%llu [\n"
		"label = \"{ <%s0> [%s] | magic 0x%04x, count %u, ibase %llu",
		gi->lname, (L)blocknr, gi->lname,
		gi->lname, ileaf->magic, icount(ileaf), (L)ibase(ileaf));

	/* draw inode attributes */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		void *attrs = ileaf->table + atdict(dict, at);
		struct inode inode = { .i_sb = btree->sb };
		decode_attrs(&inode, attrs, size);

		fprintf(gi->f,
			" | <a%d> attrs (ino %llu, size %u,"
			" block %llu, depth %d)",
			at, (L)ibase(ileaf) + at, size,
			(L)inode.btree.root.block,
			inode.btree.root.depth);
	}
	fprintf(gi->f,
		" | .....");

	/* draw offset part */
	for (at = icount(ileaf); at > 0; at--) {
		if (at == icount(ileaf)) {
			fprintf(gi->f,
				" | <o%d> offset %u (at %d)",
				at, atdict(dict, at), at);
		} else {
			fprintf(gi->f,
				" | <o%d> offset %u (at %d, ino %llu, size %u)",
				at, atdict(dict, at), at, (L)ibase(ileaf) + at,
				ileaf_attr_size(dict, at));
		}
	}

	fprintf(gi->f,
		" }\"\n"
		"shape = record\n"
		"];\n");

	/* draw allows from offset to attributes */
	for (at = 1; at < icount(ileaf); at++) {
		if (!ileaf_attr_size(dict, at))
			continue;

		fprintf(gi->f,
			"%s_%llu:o%d:w -> %s_%llu:a%d:w;\n",
			gi->lname, (L)blocknr, at,
			gi->lname, (L)blocknr, at);
	}

	/* draw inode's dtree */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		void *attrs = ileaf->table + atdict(dict, at);
		struct inode inode = { .i_sb = btree->sb };
		decode_attrs(&inode, attrs, size);

		char name[64];
		inum_t ino = ibase(ileaf) + at;
		if (ino < ARRAY_SIZE(dtree_names) && dtree_names[ino])
			sprintf(name, "%s_dtree", dtree_names[ino]);
		else
			sprintf(name, "ino%llu_dtree", (L)ino);

		if (verbose || !(drawn & DRAWN_DTREE)) {
			drawn |= DRAWN_DTREE;

			fprintf(gi->f,
				"subgraph cluster_%s {"
				"label = \"%s\"\n",
				name, name);
			struct graph_info ginfo = {
				.f = gi->f,
				.bname = name,
				.lname = "dleaf",
			};
			draw_tree(&ginfo, &inode.btree, draw_dleaf);
			fprintf(gi->f, "}\n");
		}
		fprintf(gi->f, "%s_%llu:a%d:e -> %s_bnode_%llu:n;\n",
			gi->lname, (L)blocknr, at, name,
			(L)inode.btree.root.block);
	}
}

int main(int argc, const char *argv[])
{
	poptContext popt;
	char *seekarg = NULL;
	unsigned blocksize = 0;
	struct poptOption options[] = {
		{ "seek", 's', POPT_ARG_STRING, &seekarg, 0,
		  "seek offset", "<offset>" },
		{ "blocksize", 'b', POPT_ARG_INT, &blocksize, 0,
		  "filesystem blocksize", "<size>" },
		{ "verbose", 'v', POPT_ARG_NONE, &verbose, 0,
		  "verbose", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND,
	};
	const char *volname = NULL;
	int ret = 0;

	popt = poptGetContext(NULL, argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, "<volume>");
	if (argc < 2)
		goto usage;

	int c;
	while ((c = poptGetNextOpt(popt)) >= 0)
		;
	if (c < -1)
		goto badopt;

	/* open volume, create superblock */
	volname = poptGetArg(popt);
	if (!volname)
		goto usage;

	fd_t fd = open(volname, O_RDWR, S_IRWXU);
	u64 volsize = 0;
	if (fdsize64(fd, &volsize))
		error("fdsize64 failed for '%s' (%s)",
		      volname, strerror(errno));

	int blockbits = 12;
	if (blocksize) {
		blockbits = fls(blocksize) - 1;
		if (1 << blockbits != blocksize)
			error("blocksize must be a power of two");
	}

	struct dev *dev = &(struct dev){
		.fd	= fd,
		.bits	= blockbits
	};
	init_buffers(dev, 1 << 20);

	struct sb *sb = &(struct sb){ };
	*sb = (struct sb){
		.max_inodes_per_block	= 64,
		.entries_per_node	= 20,
		.devmap			= new_map(dev, NULL),
		.blockbits		= dev->bits,
		.blocksize		= 1 << dev->bits,
		.blockmask		= (1 << dev->bits) - 1,
		.volblocks		= volsize >> dev->bits,
		.freeblocks		= volsize >> dev->bits,
		.itable = (struct btree){
			.sb			= sb,
			.ops			= &itable_ops,
			.entries_per_leaf	= 1 << (dev->bits - 6)
		}
	};

	if ((errno = -load_sb(sb)))
		goto eek;
	if (!(sb->bitmap = new_inode(sb, TUX_BITMAP_INO)))
		goto eek;
	if (!(sb->rootdir = new_inode(sb, TUX_ROOTDIR_INO)))
		goto eek;
	if (!(sb->atable = new_inode(sb, TUX_ATABLE_INO)))
		goto eek;
	if ((errno = -open_inode(sb->bitmap)))
		goto eek;
	if ((errno = -open_inode(sb->rootdir)))
		goto eek;
	if ((errno = -open_inode(sb->atable)))
		goto eek;

	struct graph_info ginfo;
	char filename[256];
	FILE *file;
	sprintf(filename, "%s.dot", volname);
	file = fopen(filename, "w");
	if (!file)
		error("coundn't open: %s\n", filename);

	ginfo.f = file;
	fprintf(ginfo.f, "digraph tux3_g {\n");

	ginfo.bname = "itable";
	ginfo.lname = "ileaf";
	draw_sb(&ginfo, sb);
	draw_tree(&ginfo, &sb->itable, draw_ileaf);
#if 0
	ginfo.bname = "bitmap_dtree";
	ginfo.lname = "dleaf";
	draw_tree(&ginfo, &sb->bitmap->btree, draw_dleaf);
	ginfo.bname = "rootdir_dtree";
	ginfo.lname = "dleaf";
	draw_tree(&ginfo, &sb->rootdir->btree, draw_dleaf);
	ginfo.bname = "atable_dtree";
	ginfo.lname = "dleaf";
	draw_tree(&ginfo, &sb->atable->btree, draw_dleaf);
#endif

	fprintf(ginfo.f, "}\n");
	fclose(ginfo.f);

	free_inode(sb->bitmap);
	free_inode(sb->rootdir);
	free_inode(sb->atable);
	free_map(sb->devmap);

out:
	/* damn, popt doesn't free str returned by poptGetArg() */
	if (volname)
		free((char *)volname);
	poptFreeContext(popt);
	return ret;

eek:
	fprintf(stderr, "%s!\n", strerror(errno));
	ret = 1;
	goto out;
usage:
	poptPrintUsage(popt, stderr, 0);
	ret = 1;
	goto out;
badopt:
	fprintf(stderr, "%s: %s\n", poptBadOption(popt, POPT_BADOPTION_NOALIAS),
		poptStrerror(c));
	ret = 1;
	goto out;
}
