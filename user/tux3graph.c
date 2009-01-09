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
static LIST_HEAD(tmpfile_head);

struct graph_info {
	FILE *f;
	char subgraph[32];	/* subgraph name */
	char filedata[32];	/* filedata name */
	const char *bname;	/* btree name */
	const char *lname;	/* leaf name */
	struct list_head link_head;
};

struct link_info {
	char link[256];
	struct list_head list;
};
#define link_entry(x)		list_entry(x, struct link_info, list)

struct dtree_info {
	FILE *f;
	struct list_head list;
};
#define dtree_entry(x)		list_entry(x, struct dtree_info, list)

static void add_link(struct graph_info *gi, const char *fmt, ...)
{
	struct link_info *linfo;
	va_list ap;

	linfo = malloc(sizeof(*linfo));
	if (!linfo)
		error("out of memory");
	INIT_LIST_HEAD(&linfo->list);
	list_add_tail(&linfo->list, &gi->link_head);

	va_start(ap, fmt);
	vsnprintf(linfo->link, sizeof(linfo->link), fmt, ap);
	va_end(ap);
}

static void write_link(struct graph_info *gi)
{
	if (!list_empty(&gi->link_head)) {
		fprintf(gi->f, "\n");
		while (!list_empty(&gi->link_head)) {
			struct link_info *l = link_entry(gi->link_head.next);
			list_del(&l->list);
			fputs(l->link, gi->f);
			free(l);
		}
	}
}

typedef void (*draw_leaf_t)(struct graph_info *, struct btree *btree, struct buffer_head *);

static void draw_sb(struct graph_info *gi, struct sb *sb)
{
	struct disksuper *txsb = &sb->super;

	fprintf(gi->f,
		"subgraph cluster_disksuper {\n"
		"label = \"disksuper\"\n"
		"tux3_sb [\n"
		"label = \"{ [disksuper] (blocknr %llu)"
		" | magic %.4s, 0x%02x, 0x%02x, 0x%02x, 0x%02x"
		" | birthdate %llu | flags 0x%016llx"
		" | <iroot0> iroot 0x%016llx (depth %u, block %llu)"
		" | aroot %llu | blockbits %u (size %u) | volblocks %llu"
		" | freeblocks %llu | nextalloc %llu"
		" | freeatom %u | atomgen %u }\"\n"
		"shape = record\n"
		"];\n"
		"}\n\n",
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

	fprintf(gi->f, "tux3_sb:iroot0:e -> %s_bnode_%llu:n;\n\n",
		gi->bname, (L)sb->itable.root.block);
}

static void draw_bnode(struct graph_info *gi, int depth, int level,
		       struct buffer_head *buffer)
{
	struct bnode *bnode = bufdata(buffer);
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

static void draw_cursor(struct graph_info *gi, struct btree *btree, struct cursor *cursor)
{
	int level;
	for (level = 0; level < btree->root.depth; level++)
		draw_bnode(gi, btree->root.depth, level, cursor->path[level].buffer);
}

static int draw_advance(struct graph_info *gi, struct btree *btree,
			struct cursor *cursor)
{
	int depth = btree->root.depth, level = depth;
	struct buffer_head *buffer;
	do {
		level_pop_brelse(cursor);
		if (!level)
			return 0;
		level--;
	} while (level_finished(cursor, level));
	while (1) {
		buffer = sb_bread(vfs_sb(btree->sb), from_be_u64(cursor->path[level].next->block));
		if (!buffer)
			goto eek;
		cursor->path[level].next++;
		if (level + 1 == depth)
			break;
		level_push(cursor, buffer, ((struct bnode *)bufdata(buffer))->entries);
		level++;
		draw_bnode(gi, depth, level, buffer);
	}
	level_push(cursor, buffer, NULL);
	return 1;
eek:
	release_cursor(cursor);
	return -EIO;
}

static void draw_tree(struct graph_info *gi, struct btree *btree, draw_leaf_t draw_leaf)
{
	struct cursor *cursor;
	struct buffer_head *buffer;

	snprintf(gi->subgraph, sizeof(gi->subgraph), "cluster_%s", gi->bname);
	fprintf(gi->f,
		"subgraph %s {\n"
		"label = \"%s\"\n",
		gi->subgraph, gi->bname);

	cursor = alloc_cursor(btree, 0);
	if (!cursor)
		error("out of memory");

	if (probe(btree, 0, cursor))
		error("tell me why!!!");

	draw_cursor(gi, btree, cursor);

	do {
		buffer = cursor_leafbuf(cursor);
		draw_leaf(gi, btree, buffer);
	} while (draw_advance(gi, btree, cursor));

	free_cursor(cursor);

	fprintf(gi->f, "}\n");

	/* add external link for this tree */
	write_link(gi);
}

typedef void (*draw_data_t)(struct graph_info *, struct btree *btree);

static void draw_bitmap(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"free bitmap:\\n"
		"1 - used block\\n"
		"0 - free block\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

static void draw_vtable(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"version table\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

static void draw_atable(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"xattr table\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

static void draw_dir(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"directory entries:\\n"
		"(filename, inum, etc.)\\n"
		"inum is used as key to search\\n"
		" inode in itable\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

static void draw_file(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"file data\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

static void draw_symlink(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n"
		"%s [\n"
		"label = \"symlink data\"\n"
		"]\n"
		"}\n",
		gi->lname, gi->lname, gi->lname);
}

#define S_SHIFT 12
static draw_data_t draw_data_table[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= draw_file,
	[S_IFDIR >> S_SHIFT]	= draw_dir,
#if 0
	[S_IFCHR >> S_SHIFT]	= draw_special,
	[S_IFBLK >> S_SHIFT]	= draw_special,
	[S_IFIFO >> S_SHIFT]	= draw_special,
	[S_IFSOCK >> S_SHIFT]	= draw_special,
#endif
	[S_IFLNK >> S_SHIFT]	= draw_symlink,
};

static inline struct group *dleaf_groups_ptr(struct btree *btree, struct dleaf *dleaf)
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

static inline struct diskextent *dleaf_extents(struct dleaf *dleaf,
					   struct group *groups,
					   int gr, int ent)
{
	struct diskextent *extents = dleaf->table;
	struct group *group;
	struct entry *entries;
	int i;

	for (i = 0; i < gr; i++) {
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

static inline struct diskextent *dleaf_extent(struct diskextent *extents, int ex)
{
	return extents + ex;
}

static void draw_dleaf(struct graph_info *gi, struct btree *btree, struct buffer_head *buffer)
{
	struct dleaf *leaf = bufdata(buffer);
	block_t blocknr = buffer->index;
	struct group *groups = dleaf_groups_ptr(btree, leaf);
	struct diskextent *extents;
	char dleaf_name[32];
	int gr;

	if (!verbose && (drawn & DRAWN_DLEAF))
		return;
	drawn |= DRAWN_DLEAF;

	snprintf(dleaf_name, sizeof(dleaf_name), "%s_%llu",
		 gi->lname, (L)blocknr);
	fprintf(gi->f,
		"%s [\n"
		"label = \"{ <%s0> [%s]"
		" | magic 0x%04x, free %u, used %u, groups %u",
		dleaf_name,
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
			"%s:gr%u:w -> %s:gr%uent%u:w;\n",
			dleaf_name, gr,
			dleaf_name, gr, 0);
		for (int ent = 0; ent < group_count(group); ent++) {
			fprintf(gi->f,
				"%s:gr%uent%u:w -> %s:gr%uent%uex%u:w;\n",
				dleaf_name, gr, ent,
				dleaf_name, gr, ent, 0);
		}
	}

	/* write link: dtree -> file data */
	snprintf(gi->filedata, sizeof(gi->filedata), "%s_data", gi->bname);
	add_link(gi, "%s:s -> %s [ltail=%s, lhead=cluster_%s];\n",
		 dleaf_name, gi->filedata, gi->subgraph, gi->filedata);
}

static inline be_u16 *ileaf_dict(struct btree *btree, struct ileaf *ileaf)
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

static void draw_ileaf(struct graph_info *gi, struct btree *btree, struct buffer_head *buffer)
{
	struct ileaf *ileaf = bufdata(buffer);
	block_t blocknr = buffer->index;
	be_u16 *dict = ileaf_dict(btree, ileaf);
	char ileaf_name[32];
	int at;

	if (!verbose && (drawn & DRAWN_ILEAF))
		return;
	drawn |= DRAWN_ILEAF;

	snprintf(ileaf_name, sizeof(ileaf_name), "%s_%llu",
		 gi->lname, (L)blocknr);
	fprintf(gi->f,
		"%s [\n"
		"label = \"{ <%s0> [%s] | magic 0x%04x, count %u, ibase %llu",
		ileaf_name, gi->lname,
		gi->lname, ileaf->magic, icount(ileaf), (L)ibase(ileaf));

	/* draw inode attributes */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		inum_t inum = ibase(ileaf) + at;
		struct inode *inode = iget(btree->sb, inum);
		if (!inode)
			error("out of memory");
		if (open_inode(inode) < 0)
			error("inode couldn't open: inum %Lu", (L)inum);

		fprintf(gi->f,
			" | <a%d> attrs (ino %llu, size %u,"
			" block %llu, depth %d)",
			at, (L)inum, size,
			(L)inode->btree.root.block,
			inode->btree.root.depth);

		free_inode(inode);
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
			"%s:o%d:w -> %s:a%d:w;\n",
			ileaf_name, at,
			ileaf_name, at);
	}

	/* draw inode's dtree */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		inum_t inum = ibase(ileaf) + at;
		struct inode *inode = iget(btree->sb, inum);
		if (!inode)
			error("out of memory");
		if (open_inode(inode) < 0)
			error("inode couldn't open: inum %Lu", (L)inum);

		char name[64];
		if (inum < ARRAY_SIZE(dtree_names) && dtree_names[inum])
			sprintf(name, "%s_dtree", dtree_names[inum]);
		else
			sprintf(name, "ino%llu_dtree", (L)inum);

		/* write link: ileaf -> dtree root bnode */
		add_link(gi, "%s:a%d:e -> %s_bnode_%llu:n;\n",
			 ileaf_name, at, name,
			 (L)inode->btree.root.block);

		draw_data_t draw_data;
		switch (inum) {
		case TUX_BITMAP_INO:
			draw_data = draw_bitmap;
			break;
		case TUX_VTABLE_INO:
			draw_data = draw_vtable;
			break;
		case TUX_ATABLE_INO:
			draw_data = draw_atable;
			break;
		case TUX_ROOTDIR_INO:
			draw_data = draw_dir;
			break;
		default:
			draw_data = draw_data_table[(inode->i_mode & S_IFMT) >> S_SHIFT];
			assert(draw_data);
			/* draw dtree */
			if (verbose || !(drawn & DRAWN_DTREE)) {
				drawn |= DRAWN_DTREE;
				break;
			}
			free_inode(inode);
			continue;
		}

		struct dtree_info *dinfo;
		/* draw dtree */
		dinfo = malloc(sizeof(*dinfo));
		if (!dinfo)
			error("out of memory");
		INIT_LIST_HEAD(&dinfo->list);
		list_add_tail(&dinfo->list, &tmpfile_head);
		dinfo->f = tmpfile64();
		struct graph_info ginfo_dtree = {
			.f = dinfo->f,
			.bname = name,
			.lname = "dleaf",
			.link_head = LIST_HEAD_INIT(ginfo_dtree.link_head),
		};
		draw_tree(&ginfo_dtree, &inode->btree, draw_dleaf);
		/* draw at least one dleaf */
		drawn &= ~DRAWN_DLEAF;

		/* draw file data */
		dinfo = malloc(sizeof(*dinfo));
		if (!dinfo)
			error("out of memory");
		INIT_LIST_HEAD(&dinfo->list);
		list_add_tail(&dinfo->list, &tmpfile_head);
		dinfo->f = tmpfile64();
		struct graph_info ginfo_data = {
			.f = dinfo->f,
			.bname = ginfo_dtree.filedata,
			.lname = ginfo_dtree.filedata,
			.link_head = LIST_HEAD_INIT(ginfo_data.link_head),
		};
		draw_data(&ginfo_data, &inode->btree);

		free_inode(inode);
	}
}

static void merge_file(FILE *dst, FILE *src)
{
	static char buf[4096];
	ssize_t size;
	int fd;

	fputc('\n', dst);

	fflush(src);
	fd = fileno(src);
	lseek(fd, 0, SEEK_SET);
	while ((size = read(fd, buf, sizeof(buf))) > 0) {
		fwrite(buf, size, 1, dst);
	}
}

static void merge_tmpfiles(struct graph_info *gi)
{
	while (!list_empty(&tmpfile_head)) {
		struct dtree_info *info = dtree_entry(tmpfile_head.next);
		list_del(&info->list);
		merge_file(gi->f, info->f);
		fclose(info->f);
		free(info);
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
		.dev			= dev,
		.blockbits		= dev->bits,
		.blocksize		= 1 << dev->bits,
		.blockmask		= (1 << dev->bits) - 1,
	};
	sb->volmap = new_inode(sb);

	if ((errno = -load_sb(sb)))
		goto eek;
	if (!(sb->bitmap = iget(sb, TUX_BITMAP_INO)))
		goto eek;
	if (!(sb->rootdir = iget(sb, TUX_ROOTDIR_INO)))
		goto eek;
	if (!(sb->atable = iget(sb, TUX_ATABLE_INO)))
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

	fprintf(file,
		"digraph tux3_g {\n"
		"graph [compound = true];\n"
		"\n");

	ginfo = (struct graph_info){
		.f = file,
		.bname = "itable",
		.lname = "ileaf",
		.link_head = LIST_HEAD_INIT(ginfo.link_head),
	};
	draw_sb(&ginfo, sb);
	draw_tree(&ginfo, &sb->itable, draw_ileaf);
	merge_tmpfiles(&ginfo);

	fprintf(ginfo.f, "}\n");
	fclose(ginfo.f);

	free_inode(sb->bitmap);
	free_inode(sb->rootdir);
	free_inode(sb->atable);
	free_inode(sb->volmap);

out:
#if 0 /* older version of popt doesn't return malloc memory */
	/* damn, popt doesn't free str returned by poptGetArg() */
	if (volname)
		free((char *)volname);
#endif
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
