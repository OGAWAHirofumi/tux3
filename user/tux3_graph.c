/*
 * Original copyright (c) 2008 Daniel Phillips <phillips at phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 *
 * $ tux3 graph [-v] volname
 * $ dot -Tpng -O volname.dot
 * $ viewer volname.dot.png
 */

#include "tux3user.h"
#include <getopt.h>

#include "walk.c"

/* Style of table on dot language */
#define TABLE_STYLE \
	"border=\"0\" cellborder=\"1\" cellpadding=\"5\" cellspacing=\"0\""

static int opt_verbose;

#define DRAWN_DTREE	(1 << 0)
#define DRAWN_DLEAF	(1 << 1)
#define DRAWN_ILEAF	(1 << 2)
#define DRAWN_OLEAF	(1 << 3)
static int drawn;
static LIST_HEAD(tmpfile_head);

struct graph_info {
	FILE *fp;
	char subgraph[32];	/* subgraph name */
	char filedata[32];	/* filedata name */
	const char *bname;	/* btree name */
	const char *lname;	/* leaf name */
	struct list_head link_head;

	void *private;
};

struct link_info {
	char link[256];
	struct list_head list;
};
#define linfo_entry(x)		list_entry(x, struct link_info, list)

struct tmpfile_info {
	FILE *fp;
	struct list_head list;
};
#define tmpfile_entry(x)	list_entry(x, struct tmpfile_info, list)

static void add_link(struct graph_info *gi, const char *fmt, ...)
{
	struct link_info *linfo;
	va_list ap;

	linfo = malloc(sizeof(*linfo));
	if (!linfo)
		strerror_exit(1, ENOMEM, "out of memory");
	INIT_LIST_HEAD(&linfo->list);
	list_add_tail(&linfo->list, &gi->link_head);

	va_start(ap, fmt);
	vsnprintf(linfo->link, sizeof(linfo->link), fmt, ap);
	va_end(ap);
}

static void write_link(struct graph_info *gi)
{
	if (!list_empty(&gi->link_head)) {
		fprintf(gi->fp, "\n");
		while (!list_empty(&gi->link_head)) {
			struct link_info *l = linfo_entry(gi->link_head.next);
			list_del(&l->list);
			fputs(l->link, gi->fp);
			free(l);
		}
	}
}

static struct tmpfile_info *alloc_tmpfile(void)
{
	struct tmpfile_info *tmpfile;

	tmpfile = malloc(sizeof(*tmpfile));
	if (!tmpfile)
		strerror_exit(1, ENOMEM, "out of memory");

	INIT_LIST_HEAD(&tmpfile->list);
	list_add_tail(&tmpfile->list, &tmpfile_head);
	tmpfile->fp = tmpfile64();

	return tmpfile;
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
		size_t n = fwrite(buf, size, 1, dst);
		if (n != 1)
			strerror_exit(1, errno, "fwrite");
	}
}

static void merge_tmpfiles(struct graph_info *gi)
{
	while (!list_empty(&tmpfile_head)) {
		struct tmpfile_info *tmpf = tmpfile_entry(tmpfile_head.next);
		list_del(&tmpf->list);
		merge_file(gi->fp, tmpf->fp);
		fclose(tmpf->fp);
		free(tmpf);
	}
}

static void draw_btree_pre(struct btree *btree, void *data)
{
	struct graph_info *gi = data;

	snprintf(gi->subgraph, sizeof(gi->subgraph), "cluster_%s", gi->bname);
	fprintf(gi->fp,
		"subgraph %s {\n"
		"label = \"%s\"\n",
		gi->subgraph, gi->bname);
}

static void draw_bnode(struct btree *btree, struct buffer_head *buffer,
		       int level, void *data)
{
	struct graph_info *gi = data;
	struct bnode *bnode = bufdata(buffer);
	block_t blocknr = buffer->index;
	struct index_entry *index = bnode->entries;
	int n;

	fprintf(gi->fp,
		"volmap_%llu [\n"
		"label = \"{ <head> [bnode] (blocknr %llu%s)"
		" | magic 0x%04x, count %u |",
		blocknr, blocknr,
		buffer_dirty(buffer) ? ", dirty" : "",
		be16_to_cpu(bnode->magic), bcount(bnode));
	for (n = 0; n < bcount(bnode); n++) {
		fprintf(gi->fp,
			" %c <f%u> key %llu, block %lld",
			n ? '|' : '{', n,
			be64_to_cpu(index[n].key), be64_to_cpu(index[n].block));
	}
	fprintf(gi->fp,
		" }}\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");

	/* write link: bnode -> bnode or leaf */
	for (n = 0; n < bcount(bnode); n++) {
		fprintf(gi->fp,
			"volmap_%llu:f%u -> volmap_%llu:head;\n",
			blocknr, n,
			be64_to_cpu(index[n].block));
	}
}

static void draw_btree_post(struct btree *btree, void *data)
{
	struct graph_info *gi = data;

	fprintf(gi->fp, "}\n");

	/* add external link for this tree */
	write_link(gi);
}

struct draw_data_ops {
	void (*draw_start)(struct graph_info *gi, struct btree *btree);
	void (*draw_data)(struct graph_info *gi, struct btree *btree,
			  struct buffer_head *dleafbuf,
			  block_t index, block_t block, unsigned count);
	void (*draw_end)(struct graph_info *gi, struct btree *btree);
};

static void draw_subdata_start(struct graph_info *gi, struct btree *btree,
			       const char *postfix)
{
	fprintf(gi->fp, "%s%s [\n", gi->lname, postfix);
}

static void draw_data_start(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n",
		gi->lname, gi->lname);

	draw_subdata_start(gi, btree, "");
}

static void draw_data(struct graph_info *gi, struct btree *btree,
		      struct buffer_head *dleafbuf,
		      block_t index, block_t block, unsigned count)
{
}

static void draw_subdata_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp,
		"shape = record\n"
		"];\n");
}

static void draw_data_end(struct graph_info *gi, struct btree *btree)
{
	draw_subdata_end(gi, btree);

	fprintf(gi->fp, "}\n");
}

static void draw_bitmap_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"{ dump of bitmap data");
}

static int bitmap_has_dirty;

static void draw_bitmap_data(struct graph_info *gi, struct btree *btree,
			     struct buffer_head *dleafbuf,
			     block_t index, block_t block, unsigned count)
{
	struct sb *sb = btree->sb;
	struct inode *bitmap = sb->bitmap;
	void *data;

	for (unsigned i = 0; i < count; i++) {
		unsigned idx, size = sb->blocksize * 8;
		struct buffer_head *buffer;

		/* bit offset from index 0 and bit 0 */
		block_t offset = (index + i) * size;

		fprintf(gi->fp, " | index %llu:", (index + i));
		buffer = blockread(mapping(bitmap), index + i);
		assert(buffer);
		data = bufdata(buffer);

		idx = find_next_bit_le(data, size, 0);
		while (idx < size) {
			block_t start, end;

			start = offset + idx;
			idx = find_next_zero_bit_le(data, size, idx + 1);
			end = offset + idx - 1;

			if (start != end)
				fprintf(gi->fp, " %llu-%llu,", start, end);
			else
				fprintf(gi->fp, " %llu,", start);

			if (idx >= size)
				break;
			idx = find_next_bit_le(data, size, idx + 1);
			if (idx >= size)
				break;
		}
		fprintf(gi->fp, " \\l"); /* left align */

		if (buffer_dirty(buffer))
			bitmap_has_dirty = 1;
		blockput(buffer);
	}
}

static void draw_bitmap_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp,
		" }\"\n"
		"%s",
		bitmap_has_dirty ? "color = red\n" : "");
	draw_data_end(gi, btree);
}

struct draw_data_ops draw_bitmap = {
	.draw_start	= draw_bitmap_start,
	.draw_data	= draw_bitmap_data,
	.draw_end	= draw_bitmap_end,
};

static int countmap_has_dirty;

static void draw_countmap_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"{ dump of countmap data");
}

static void draw_countmap_data(struct graph_info *gi, struct btree *btree,
			     struct buffer_head *dleafbuf,
			     block_t index, block_t block, unsigned count)
{
	struct sb *sb = btree->sb;
	struct inode *countmap = sb->countmap;

	for (unsigned i = 0; i < count; i++) {
		unsigned size = sb->blocksize >> 1;
		block_t group = (index + i) << (sb->blockbits - 1);
		struct buffer_head *buffer;
		__be16 *p, *limit;

		fprintf(gi->fp, " | index %llu", (index + i));
		buffer = blockread(mapping(countmap), index + i);
		assert(buffer);

		p = bufdata(buffer);
		limit = p + size;
		while (p < limit) {
			if (*p) {
				fprintf(gi->fp, " | group %llu: %u",
					group, be16_to_cpu(*p));
			}
			p++;
			group++;
		}

		fprintf(gi->fp, " \\l"); /* left align */

		if (buffer_dirty(buffer))
			countmap_has_dirty = 1;
		blockput(buffer);
	}
}

static void draw_countmap_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp,
		" }\"\n"
		"%s",
		countmap_has_dirty ? "color = red\n" : "");
	draw_data_end(gi, btree);
}

struct draw_data_ops draw_countmap = {
	.draw_start	= draw_countmap_start,
	.draw_data	= draw_countmap_data,
	.draw_end	= draw_countmap_end,
};

static void draw_vtable_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"version table\"\n");
}

struct draw_data_ops draw_vtable = {
	.draw_start	= draw_vtable_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static void draw_atable_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"{ dump of atable");
}

static void __draw_dir_data(struct graph_info *gi, struct btree *btree,
			    struct buffer_head *dleafbuf,
			    struct buffer_head *buffer, block_t block,
			    int atable)
{
	struct sb *sb = btree->sb;
	struct tux3_dirent *entry = bufdata(buffer);
	struct tux3_dirent *limit = (void *)entry + sb->blocksize;

	while (entry < limit) {
		fprintf(gi->fp,
			" | inum %llu, rec_len %hu, name_len %u,"
			" type %u, '%.*s'",
			be64_to_cpu(entry->inum), be16_to_cpu(entry->rec_len),
			entry->name_len, entry->type,
			(int)entry->name_len, entry->name);

		entry = (void *)entry + be16_to_cpu(entry->rec_len);
	}
}

static void draw_atable_atomref(struct graph_info *gi, struct btree *btree,
				struct buffer_head *low_buf,
				struct buffer_head *hi_buf)
{
	static int prev_atomref = 1;

	struct sb *sb = btree->sb;
	unsigned shift = sb->blockbits - 1; /* atomref size is (1 << 1) bytes */
	unsigned atom_base = (bufindex(low_buf) - sb->atomref_base) << shift;
	__be16 *limit, *base, *low = bufdata(low_buf), *hi = bufdata(hi_buf);

	base = low;
	limit = (void *)low + sb->blocksize;
	while (low < limit) {
		unsigned atom = atom_base + (low - base);
		unsigned ref = (u32)be16_to_cpup(hi) << 16 | be16_to_cpup(low);

		if (ref) {
			if (!prev_atomref)
				fprintf(gi->fp, " | ...");

			fprintf(gi->fp,
				" | low 0x%04hx, hi 0x%04hx"
				" (atom %u, refcnt %u)",
				be16_to_cpup(low), be16_to_cpup(hi), atom, ref);

			prev_atomref = 1;
		} else
			prev_atomref = 0;

		low++;
		hi++;
	}
}

static void draw_atable_unatom(struct graph_info *gi, struct btree *btree,
			       struct buffer_head *buffer)
{
	struct sb *sb = btree->sb;
	unsigned shift = sb->blockbits - 3; /* unatom size is (1 << 3) bytes */
	unsigned atom_base = (bufindex(buffer) - sb->unatom_base) << shift;
	__be64 *limit, *base, *ptr = bufdata(buffer);

	base = ptr;
	limit = (void *)ptr + sb->blocksize;
	while (ptr < limit) {
		unsigned atom = atom_base + (ptr - base);

		if (atom < sb->atomgen) {
			fprintf(gi->fp,
				" | where 0x%08llx (atom %u)",
				be64_to_cpup(ptr), atom);

		}

		ptr++;
	}
}

static void draw_atable_data(struct graph_info *gi, struct btree *btree,
			     struct buffer_head *dleafbuf,
			     block_t index, block_t block, unsigned count)
{
	static int start_atomref = 1, start_unatom = 1;

	struct sb *sb = btree->sb;
	struct buffer_head *buffer, *hi_buf;

	for (unsigned i = 0; i < count; i++) {
		buffer = blockread(mapping(sb->atable), index + i);
		assert(buffer);

		if (index < sb->atomref_base) {
			/* atom name table */
			__draw_dir_data(gi, btree, dleafbuf, buffer, block+i,1);
		} else if (index < sb->unatom_base) {
			/* atom refcount table */
			if (start_atomref) {
				start_atomref = 0;
				fprintf(gi->fp, " }\"\n");
				draw_subdata_end(gi, btree);
				draw_subdata_start(gi, btree, "_atomref");
				fprintf(gi->fp, "label = \"{ dump of atomref");
			}

			/* Dump low and high at once */
			if ((index + i) & 1)
				goto next;

			hi_buf = blockread(mapping(sb->atable), index + i + 1);
			assert(hi_buf);

			draw_atable_atomref(gi, btree, buffer, hi_buf);

			blockput(hi_buf);
		} else {
			/* unatom table */
			if (start_unatom) {
				start_unatom = 0;
				fprintf(gi->fp, " }\"\n");
				draw_subdata_end(gi, btree);
				draw_subdata_start(gi, btree, "_unatom");
				fprintf(gi->fp, "label = \"{ dump of unatom");
			}

			draw_atable_unatom(gi, btree, buffer);
		}

next:
		blockput(buffer);
	}
}

static void draw_atable_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp, " }\"\n");
	draw_data_end(gi, btree);
}

struct draw_data_ops draw_atable = {
	.draw_start	= draw_atable_start,
	.draw_data	= draw_atable_data,
	.draw_end	= draw_atable_end,
};

static void draw_dir_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp,
		"label = \"{ dump of directory");
}

static void draw_dir_data(struct graph_info *gi, struct btree *btree,
			  struct buffer_head *dleafbuf,
			  block_t index, block_t block, unsigned count)
{
	struct buffer_head *buffer;

	for (unsigned i = 0; i < count; i++) {
		buffer = blockread(mapping(btree_inode(btree)), index + i);
		assert(buffer);

		__draw_dir_data(gi, btree, dleafbuf, buffer, block + i, 0);

		blockput(buffer);
	}
}

static void draw_dir_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->fp,
		" }\"\n");
	draw_data_end(gi, btree);
}

struct draw_data_ops draw_dir = {
	.draw_start	= draw_dir_start,
	.draw_data	= draw_dir_data,
	.draw_end	= draw_dir_end,
};

static void draw_file_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"file data\"\n");
}

struct draw_data_ops draw_file = {
	.draw_start	= draw_file_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static void draw_symlink_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->fp, "label = \"symlink data\"\n");
}

static struct draw_data_ops draw_symlink = {
	.draw_start	= draw_symlink_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static const char *get_dleaf_name(struct buffer_head *dleaf_buf)
{
	static char name[32];
	block_t blocknr = dleaf_buf->index;
	snprintf(name, sizeof(name), "volmap_%llu", blocknr);
	return name;
}

static void draw_dleaf_start(struct graph_info *gi,
			     struct buffer_head *dleafbuf)
{
	block_t blocknr = dleafbuf->index;

	fprintf(gi->fp,
		"%s [\n"
		"label = \"{ <head> [%s] (blocknr %llu%s)",
		get_dleaf_name(dleafbuf), gi->lname, blocknr,
		buffer_dirty(dleafbuf) ? ", dirty" : "");
}

static void draw_dleaf_end(struct graph_info *gi, struct buffer_head *dleafbuf)
{
	fprintf(gi->fp,
		" }\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(dleafbuf) ? "color = red\n" : "");
}

static void draw_dleaf_extent(struct btree *btree, struct buffer_head *dleafbuf,
			      block_t index, block_t block, unsigned count,
			      void *data)
{
	struct graph_info *dtree_gi = data;
	struct graph_info *data_gi = dtree_gi->private;
	struct draw_data_ops *draw_data_ops = data_gi->private;

	draw_data_ops->draw_data(data_gi, btree, dleafbuf,
				 index, block, count);
}

static void draw_dleaf_entry(struct btree *btree, struct buffer_head *dleafbuf,
			      unsigned prev_count,
			      unsigned version, block_t index, block_t block,
			      int is_sentinel, void *data)
{
	struct graph_info *dtree_gi = data;

	if (prev_count)
		fprintf(dtree_gi->fp, " (count %u)", prev_count);

	fprintf(dtree_gi->fp,
		" | verhi 0x%04x, logical %llu,"
		" verlo 0x%04x, physical %llu",
		version >> VER_BITS, index,
		version & VER_MASK, block);

	if (is_sentinel)
		fprintf(dtree_gi->fp, " (sentinel)");
}

static struct walk_dleaf_ops draw_dleaf_ops = {
	.extent = draw_dleaf_extent,
	.entry = draw_dleaf_entry,
};

static void draw_dleaf(struct btree *btree, struct buffer_head *dleafbuf,
		       void *data)
{
	struct graph_info *gi = data;
	struct dleaf *dleaf = bufdata(dleafbuf);

	if (!opt_verbose && (drawn & DRAWN_DLEAF))
		return;
	drawn |= DRAWN_DLEAF;

	draw_dleaf_start(gi, dleafbuf);

	fprintf(gi->fp,
		" | magic 0x%04x, count %u",
		be16_to_cpu(dleaf->magic), be16_to_cpu(dleaf->count));

	walk_dleaf(btree, dleafbuf, &draw_dleaf_ops, gi);

	draw_dleaf_end(gi, dleafbuf);

	/* write link: dleaf -> file data */
	add_link(gi, "%s:s -> %s [ltail=%s, lhead=cluster_%s];\n",
		 get_dleaf_name(dleafbuf), gi->filedata,
		 gi->subgraph, gi->filedata);
}

static void draw_direct_extent(struct btree *btree,
			       struct buffer_head *ileafbuf,
			       block_t index, block_t block, unsigned count,
			       void *data)
{
	struct graph_info *dtree_gi = data;
	struct graph_info *data_gi = dtree_gi->private;
	struct draw_data_ops *draw_data_ops = data_gi->private;

	draw_data_ops->draw_data(data_gi, btree, NULL, index, block, count);
}

static struct walk_btree_ops draw_dtree_ops = {
	.pre	= draw_btree_pre,
	.bnode	= draw_bnode,
	.leaf	= draw_dleaf,
	.post	= draw_btree_post,

	.extent	= draw_direct_extent,
};

static struct {
	const char *name;
	struct draw_data_ops *info;
}  dtree_types[] = {
	[TUX_BITMAP_INO] =  {
		.name = "bitmap",
		.info = &draw_bitmap,
	},
	[TUX_COUNTMAP_INO] =  {
		.name = "countmap",
		.info = &draw_countmap,
	},
	[TUX_VTABLE_INO] = {
		.name = "vtable",
		.info = &draw_vtable,
	},
	[TUX_ATABLE_INO] = {
		.name = "atable",
		.info = &draw_atable,
	},
	[TUX_ROOTDIR_INO] = {
		.name = "rootdir",
		.info = &draw_dir,
	},
};

#define S_SHIFT 12
static struct draw_data_ops *dtree_funcs[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= &draw_file,
	[S_IFDIR >> S_SHIFT]	= &draw_dir,
#if 0
	[S_IFCHR >> S_SHIFT]	= &draw_special,
	[S_IFBLK >> S_SHIFT]	= &draw_special,
	[S_IFIFO >> S_SHIFT]	= &draw_special,
	[S_IFSOCK >> S_SHIFT]	= &draw_special,
#endif
	[S_IFLNK >> S_SHIFT]	= &draw_symlink,
};

static void draw_ileaf_cb(struct buffer_head *ileafbuf, int at,
			  struct inode *inode, void *data)
{
	if (has_no_root(&tux_inode(inode)->btree))
		return;

	struct graph_info *gi = data;
	struct btree *dtree = &tux_inode(inode)->btree;
	inum_t inum = tux_inode(inode)->inum;
	block_t blocknr = bufindex(ileafbuf);	/* blocknr of ileaf */

	struct draw_data_ops *draw_data_ops;
	char bname[64];
	int special_inode;
	if (inum < ARRAY_SIZE(dtree_types) && dtree_types[inum].name) {
		sprintf(bname, "%s_dtree", dtree_types[inum].name);
		draw_data_ops = dtree_types[inum].info;
		special_inode = 1;
	} else {
		int file_type = (inode->i_mode & S_IFMT) >> S_SHIFT;
		sprintf(bname, "ino%llu_dtree", inum);
		draw_data_ops = dtree_funcs[file_type];
		special_inode = 0;
	}
	assert(draw_data_ops);

	if (!special_inode) {
		if (!opt_verbose && (drawn & DRAWN_DTREE))
			return;

		drawn |= DRAWN_DTREE;
	}

	/* for draw dtree */
	struct tmpfile_info *tmp = alloc_tmpfile();

	struct graph_info ginfo_dtree = {
		.fp = tmp->fp,
		.bname = bname,
		.lname = "dleaf",
		.link_head = LIST_HEAD_INIT(ginfo_dtree.link_head),
	};
	snprintf(ginfo_dtree.filedata, sizeof(ginfo_dtree.filedata),
		 "%s_data", bname);

	if (has_direct_extent(dtree)) {
		/* write link: ileaf -> file data */
		add_link(gi, "volmap_%llu:a%d:e -> %s;\n",
			 blocknr, at, ginfo_dtree.filedata);
	} else {
		/* write link: ileaf -> dtree root bnode */
		add_link(gi, "volmap_%llu:a%d:e -> volmap_%llu:n;\n",
			 blocknr, at,
			 dtree->root.block);
	}

	/* for draw file data */
	tmp = alloc_tmpfile();
	struct graph_info ginfo_data = {
		.fp = tmp->fp,
		.bname = ginfo_dtree.filedata,
		.lname = ginfo_dtree.filedata,
		.link_head = LIST_HEAD_INIT(ginfo_data.link_head),
		.private = draw_data_ops,
	};

	ginfo_dtree.private = &ginfo_data;

	draw_data_ops->draw_start(&ginfo_data, dtree);
	walk_dtree(dtree, ileafbuf, &draw_dtree_ops, &ginfo_dtree);
	draw_data_ops->draw_end(&ginfo_data, dtree);

	/* draw at least one dleaf */
	drawn &= ~DRAWN_DLEAF;
}

typedef void (*draw_ileaf_attr_t)(struct graph_info *, struct btree *,
				  struct buffer_head *, inum_t, void *, u16);

static void draw_ileaf_attr(struct graph_info *gi, struct btree *btree,
			    struct buffer_head *ileafbuf, inum_t inum,
			    void *attrs, u16 size)
{
	struct sb *sb = btree->sb;
	struct inode *inode = rapid_open_inode(sb, NULL, 0);

	/* Check there is orphaned inode */
	struct inode *cache_inode = tux3_ilookup(sb, inum);
	int orphan = 0;
	if (cache_inode) {
		orphan = tux3_inode_is_orphan(tux_inode(cache_inode));
		iput(cache_inode);
	}

	iattr_ops.decode(btree, inode, attrs, size);

	fprintf(gi->fp,
		"%s"
		"attrs (ino %llu, size %u, direct %d, block %llu, %s %d%s)"
		"%s",
		orphan ? "<font color=\"blue\">" : "",
		inum, size,
		has_direct_extent(&tux_inode(inode)->btree),
		tux_inode(inode)->btree.root.block,
		has_direct_extent(&tux_inode(inode)->btree) ? "count" : "depth",
		tux_inode(inode)->btree.root.depth,
		orphan ? ", orphan" : "",
		orphan ? "</font>" : "");

	free_xcache(inode);
	free_map(inode->map);
}

static void __draw_ileaf(struct graph_info *gi, struct btree *btree,
			 struct buffer_head *ileafbuf,
			 draw_ileaf_attr_t draw_ileaf_attr)
{
	struct ileaf *ileaf = bufdata(ileafbuf);
	__be16 *dict = ileaf_dict(btree, ileaf);
	block_t blocknr = ileafbuf->index;
	int at;

	fprintf(gi->fp,
		"volmap_%llu [\n"
		"label =\n"
		"<<table " TABLE_STYLE ">\n"
		"  <tr>\n"
		"    <td port=\"head\">[%s] (blocknr %llu%s)</td>\n"
		"  </tr>\n"
		"  <tr>\n"
		"    <td>magic 0x%04x, count %u, ibase %llu</td>\n"
		"  </tr>\n",
		blocknr,
		gi->lname, blocknr,
		buffer_dirty(ileafbuf) ? ", dirty" : "",
		be16_to_cpu(ileaf->magic), icount(ileaf), ibase(ileaf));

	/* draw inode attributes */
	u16 offset = 0, limit, size;
	for (at = 0; at < icount(ileaf); at++) {
		limit = __atdict(dict, at + 1);
		if (offset >= limit)
			continue;
		size = limit - offset;

		inum_t inum = ibase(ileaf) + at;
		void *attrs = ileaf->table + offset;

		offset = limit;

		fprintf(gi->fp,
			"  <tr>\n"
			"    <td port=\"a%d\">",
			at);

		draw_ileaf_attr(gi, btree, ileafbuf, inum, attrs, size);

		fprintf(gi->fp,
			"</td>\n"
			"  </tr>\n");
	}
	fprintf(gi->fp,
		"  <tr>\n"
		"   <td>.....</td>\n"
		"  </tr>\n");

	/* draw offset part */
	for (at = icount(ileaf) - 1; at >= 0; at--) {
		fprintf(gi->fp,
			"  <tr>\n"
			"   <td port=\"o%d\">"
			"limit %u (offset %u, size %u, ino %llu)</td>\n"
			"  </tr>\n",
			at, atdict(dict, at + 1), atdict(dict, at),
			ileaf_attr_size(dict, at), ibase(ileaf) + at);
	}

	fprintf(gi->fp,
		"</table>>\n"
		"shape = plaintext\n"
		"%s"
		"];\n",
		buffer_dirty(ileafbuf) ? "color = red\n" : "");

	/* draw allows from offset to attributes */
	for (at = 0; at < icount(ileaf); at++) {
		if (!ileaf_attr_size(dict, at))
			continue;

		/* write link: ileaf offset -> ileaf attrs */
		fprintf(gi->fp,
			"volmap_%llu:o%d:w -> volmap_%llu:a%d:w;\n",
			blocknr, at,
			blocknr, at);
	}
}

static void draw_ileaf(struct btree *btree, struct buffer_head *ileafbuf,
		       void *data)
{
	struct graph_info *gi = data;

	if (!opt_verbose && (drawn & DRAWN_ILEAF))
		return;
	drawn |= DRAWN_ILEAF;

	__draw_ileaf(gi, btree, ileafbuf, draw_ileaf_attr);

	walk_ileaf(btree, ileafbuf, draw_ileaf_cb, gi);
}

static struct walk_btree_ops draw_itree_ops = {
	.pre	= draw_btree_pre,
	.bnode	= draw_bnode,
	.leaf	= draw_ileaf,
	.post	= draw_btree_post,
};

static void draw_oleaf_attr(struct graph_info *gi, struct btree *btree,
			    struct buffer_head *oleafbuf, inum_t inum,
			    void *attrs, u16 size)
{
	fprintf(gi->fp, "attrs (ino %llu, size %u)", inum, size);
}

static void draw_oleaf(struct btree *btree, struct buffer_head *oleafbuf,
		       void *data)
{
	struct graph_info *gi = data;

	if (!opt_verbose && (drawn & DRAWN_OLEAF))
		return;
	drawn |= DRAWN_OLEAF;

	__draw_ileaf(gi, btree, oleafbuf, draw_oleaf_attr);
}

static struct walk_btree_ops draw_otree_ops = {
	.pre	= draw_btree_pre,
	.bnode	= draw_bnode,
	.leaf	= draw_oleaf,
	.post	= draw_btree_post,
};

static void draw_log_pre(struct sb *sb, struct buffer_head *buffer,
			 unsigned logcount, int obsolete, void *data)
{
	struct graph_info *gi = data;
	struct logblock *log = bufdata(buffer);

	fprintf(gi->fp,
		"logchain_%llu [\n"
		"label = \"{ <logchain_%llu> [log] (blocknr %llu%s)"
		" | <f0> magic 0x%04x, bytes %u, logchain %llu",
		bufindex(buffer), bufindex(buffer), bufindex(buffer),
		buffer_dirty(buffer) ? ", dirty" : "",
		be16_to_cpu(log->magic), be16_to_cpu(log->bytes),
		be64_to_cpu(log->logchain));
}

static void draw_log(struct sb *sb, struct buffer_head *buffer,
		     u8 code, u8 *p, unsigned len, int obsolete, void *data)
{
	struct graph_info *gi = data;

	fprintf(gi->fp, " | [%s] ", log_name[code]);

	switch (code) {
	case LOG_BALLOC:
	case LOG_BFREE:
	case LOG_BFREE_ON_UNIFY:
	case LOG_BFREE_RELOG: {
		u32 count;
		u64 block;
		p = decode32(p, &count);
		p = decode48(p, &block);
		fprintf(gi->fp, "count %u, block %llu ", count, block);
		break;
	}
	case LOG_LEAF_REDIRECT:
	case LOG_BNODE_REDIRECT: {
		u64 old, new;
		p = decode48(p, &old);
		p = decode48(p, &new);
		fprintf(gi->fp, "old %llu, new %llu ", old, new);
		break;
	}
	case LOG_LEAF_FREE:
	case LOG_BNODE_FREE: {
		u64 block;
		p = decode48(p, &block);
		fprintf(gi->fp, "%s %llu ",
			code == LOG_LEAF_FREE ? "leaf" : "bnode",
			block);
		break;
	}
	case LOG_BNODE_ROOT: {
		u64 root, left, right, rkey;
		unsigned count = *p++;
		p = decode48(p, &root);
		p = decode48(p, &left);
		p = decode48(p, &right);
		p = decode48(p, &rkey);
		fprintf(gi->fp,
			"count %u, root %llu, left %llu, right %llu, "
			"right key %llu ",
			count, root, left, right, rkey);
		break;
	}
	case LOG_BNODE_SPLIT: {
		u64 src, dest;
		unsigned pos;
		p = decode16(p, &pos);
		p = decode48(p, &src);
		p = decode48(p, &dest);
		fprintf(gi->fp, "pos %u, src %llu, dest %llu ",
			pos, src, dest);
		break;
	}
	case LOG_BNODE_ADD:
	case LOG_BNODE_UPDATE: {
		u64 parent, child, key;
		p = decode48(p, &parent);
		p = decode48(p, &child);
		p = decode48(p, &key);
		fprintf(gi->fp, "parent %llu, child %llu, key %llu ",
			parent, child, key);
		break;
	}
	case LOG_BNODE_MERGE:
	{
		u64 src, dst;
		p = decode48(p, &src);
		p = decode48(p, &dst);
		fprintf(gi->fp, "src %llu, dst %llu ", src, dst);
		break;
	}
	case LOG_BNODE_DEL:
	{
		unsigned count;
		u64 bnode, key;
		p = decode16(p, &count);
		p = decode48(p, &bnode);
		p = decode48(p, &key);
		fprintf(gi->fp, "count %u, bnode %llu, key %llu ",
			count, bnode, key);
		break;
	}
	case LOG_BNODE_ADJUST:
	{
		u64 node, from, to;
		p = decode48(p, &node);
		p = decode48(p, &from);
		p = decode48(p, &to);
		fprintf(gi->fp, "node %llu, from %llu, to %llu ",
			node, from, to);
		break;
	}
	case LOG_ORPHAN_ADD:
	case LOG_ORPHAN_DEL: {
		unsigned version;
		u64 inum;
		p = decode16(p, &version);
		p = decode48(p, &inum);
		fprintf(gi->fp, "version %x, inum %llu ",
			version, inum);
		break;
	}
	case LOG_FREEBLOCKS: {
		u64 freeblocks;
		p = decode48(p, &freeblocks);
		fprintf(gi->fp, "freeblocks %llu ", freeblocks);
		break;
	}
	case LOG_UNIFY:
	case LOG_DELTA:
		break;
	default:
		fprintf(stderr, "Unknown log code 0x%x!\n", code);
		assert(0);
		break;
	}
}

static void draw_log_post(struct sb *sb, struct buffer_head *buffer,
			  unsigned logcount, int obsolete, void *data)
{
	struct graph_info *gi = data;
	struct logblock *log = bufdata(buffer);

	fprintf(gi->fp,
		"}\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");

	/* If not last logblock, write link */
	if (logcount > 1) {
		/* write link: logblock -> logblock */
		fprintf(gi->fp,
			"logchain_%llu:f0:e -> logchain_%llu:n;\n",
			bufindex(buffer), be64_to_cpu(log->logchain));
	}
}

static struct walk_logchain_ops draw_logchain_ops = {
	.pre	= draw_log_pre,
	.log	= draw_log,
	.post	= draw_log_post,
};

static void draw_logchain(struct graph_info *gi, struct sb *sb)
{
	fprintf(gi->fp,
		"subgraph cluster_logchain {\n"
		"label = \"logchain\"\n");

	walk_logchain(sb, &draw_logchain_ops, gi);

	fprintf(gi->fp,
		"}\n\n");
}

static void draw_sb(struct graph_info *gi, struct sb *sb)
{
	struct disksuper *txsb = &sb->super;

	fprintf(gi->fp,
		"subgraph cluster_disksuper {\n"
		"label = \"disksuper\"\n"
		"tux3_sb [\n"
		"label = \"{ [disksuper] (blocknr %llu, freeblocks %llu)"
		" | magic %.4s, 0x%02x, 0x%02x, 0x%02x, 0x%02x"
		" | birthdate %llu | flags 0x%016llx"
		" | <iroot0> iroot 0x%016llx (depth %u, block %llu)"
		" | <oroot0> oroot 0x%016llx (depth %u, block %llu)"
		" | blockbits %u (size %u) | volblocks %llu | usedinodes %llu"
		" | nextblock %llu"
		" | atomdictsize %Lu | freeatom %u | atomgen %u"
		" | <logchain_%llu> logchain %llu | logcount %u"
		" }\"\n"
		"shape = record\n"
		"];\n"
		"}\n\n",
		(block_t)SB_LOC >> sb->blockbits, sb->freeblocks,
		txsb->magic,
		(u8)txsb->magic[4], (u8)txsb->magic[5],
		(u8)txsb->magic[6], (u8)txsb->magic[7],
		be64_to_cpu(txsb->birthdate),
		be64_to_cpu(txsb->flags),
		be64_to_cpu(txsb->iroot),
		itree_btree(sb)->root.depth, itree_btree(sb)->root.block,
		be64_to_cpu(txsb->oroot),
		otree_btree(sb)->root.depth, otree_btree(sb)->root.block,
		sb->blockbits, sb->blocksize,
		be64_to_cpu(txsb->volblocks), be64_to_cpu(txsb->usedinodes),
		be64_to_cpu(txsb->nextblock),
		be64_to_cpu(txsb->atomdictsize),
		be32_to_cpu(txsb->freeatom), be32_to_cpu(txsb->atomgen),
		be64_to_cpu(txsb->logchain), be64_to_cpu(txsb->logchain),
		be32_to_cpu(txsb->logcount));

	/* write link: sb -> itree root */
	fprintf(gi->fp, "tux3_sb:iroot0:e -> volmap_%llu:n;\n\n",
		itree_btree(sb)->root.block);
	/* write link: sb -> otree root */
	fprintf(gi->fp, "tux3_sb:oroot0:e -> volmap_%llu:n;\n\n",
		otree_btree(sb)->root.block);
	/* write link: sb -> logchain */
	fprintf(gi->fp, "tux3_sb:logchain_%llu:e -> logchain_%llu:n;\n\n",
		be64_to_cpu(txsb->logchain), be64_to_cpu(txsb->logchain));
}

static int graph_main(struct sb *sb, const char *volname, int verbose)
{
	int err;

	opt_verbose = verbose;

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp))
		return PTR_ERR(rp);

	struct graph_info ginfo;
	char filename[256];
	FILE *file;
	sprintf(filename, "%s.dot", volname);
	file = fopen(filename, "w");
	if (!file)
		strerror_exit(1, errno, "coundn't open %s\n", filename);

	fprintf(file,
		"digraph tux3_g {\n"
		"graph [compound = true];\n"
		"\n");

	ginfo = (struct graph_info){
		.fp = file,
		.bname = "itree",
		.lname = "ileaf",
		.link_head = LIST_HEAD_INIT(ginfo.link_head),
	};
	draw_sb(&ginfo, sb);
	draw_logchain(&ginfo, sb);
	walk_btree(itree_btree(sb), &draw_itree_ops, &ginfo);

	ginfo = (struct graph_info){
		.fp = file,
		.bname = "otree",
		.lname = "oleaf",
		.link_head = LIST_HEAD_INIT(ginfo.link_head),
	};
	walk_btree(otree_btree(sb), &draw_otree_ops, &ginfo);

	merge_tmpfiles(&ginfo);

	fprintf(ginfo.fp, "}\n");
	fclose(ginfo.fp);

	err = replay_stage3(rp, 0);
	if (err)
		return err;

	return 0;
}
