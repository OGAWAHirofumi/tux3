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

#include "tux3user.h"
#include <getopt.h>

/* tux3graph has to access internal structure */
#include "kernel/btree.c"
#include "kernel/dleaf.c"
#include "kernel/dleaf2.c"
#include "kernel/ileaf.c"

/* Style of table on dot language */
#define TABLE_STYLE \
	"border=\"0\" cellborder=\"1\" cellpadding=\"5\" cellspacing=\"0\""

static const char itable_name[] = "itable";
static const char otable_name[] = "otable";

static int verbose;
#define DRAWN_DTREE	(1 << 0)
#define DRAWN_DLEAF	(1 << 1)
#define DRAWN_ILEAF	(1 << 2)
#define DRAWN_OLEAF	(1 << 3)
static int drawn;
static LIST_HEAD(tmpfile_head);

struct graph_info {
	FILE *f;
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
			struct link_info *l = linfo_entry(gi->link_head.next);
			list_del(&l->list);
			fputs(l->link, gi->f);
			free(l);
		}
	}
}

static struct dtree_info *alloc_tmpfile(void)
{
	struct dtree_info *dinfo;

	dinfo = malloc(sizeof(*dinfo));
	if (!dinfo)
		error("out of memory");

	INIT_LIST_HEAD(&dinfo->list);
	list_add_tail(&dinfo->list, &tmpfile_head);
	dinfo->f = tmpfile64();

	return dinfo;
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
			error("fwrite error: %s", strerror(errno));
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

typedef void (*draw_leaf_t)(struct graph_info *, struct btree *btree,
			    struct buffer_head *, void *);

static void draw_bnode(struct graph_info *gi, struct buffer_head *buffer)
{
	struct bnode *bnode = bufdata(buffer);
	block_t blocknr = buffer->index;
	struct index_entry *index = bnode->entries;
	int n;

	fprintf(gi->f,
		"volmap_%llu [\n"
		"label = \"{ <head> [bnode] (blocknr %llu%s)"
		" | magic 0x%04x, count %u |",
		blocknr, blocknr,
		buffer_dirty(buffer) ? ", dirty" : "",
		be16_to_cpu(bnode->magic), bcount(bnode));
	for (n = 0; n < bcount(bnode); n++) {
		fprintf(gi->f,
			" %c <f%u> key %llu, block %lld",
			n ? '|' : '{', n,
			be64_to_cpu(index[n].key), be64_to_cpu(index[n].block));
	}
	fprintf(gi->f,
		" }}\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");

	/* write link: bnode -> bnode or leaf */
	for (n = 0; n < bcount(bnode); n++) {
		fprintf(gi->f,
			"volmap_%llu:f%u -> volmap_%llu:head;\n",
			blocknr, n,
			be64_to_cpu(index[n].block));
	}
}

static void walk_btree(struct graph_info *gi, struct btree *btree,
		       draw_leaf_t draw_leaf, void *data)
{
	struct cursor *cursor;
	struct buffer_head *buffer;

	cursor = alloc_cursor(btree, 0);
	if (!cursor)
		error("out of memory");

	if (cursor_read_root(cursor) < 0)
		error("cursor_read_root() error");

	buffer = cursor->path[cursor->level].buffer;
	draw_bnode(gi, buffer);

	while (1) {
		int ret = cursor_advance_down(cursor);
		if (ret < 0)
			error("cursor_advance_down() error");
		if (ret) {
			buffer = cursor->path[cursor->level].buffer;
			draw_bnode(gi, buffer);
			continue;
		}

		buffer = cursor_leafbuf(cursor);
		draw_leaf(gi, btree, buffer, data);

		do {
			if (!cursor_advance_up(cursor)) {
				free_cursor(cursor);
				return;
			}
		} while (cursor_level_finished(cursor));
	}
}

static void draw_btree(struct graph_info *gi, struct btree *btree,
		       draw_leaf_t draw_leaf, void *data)
{
	if (!has_root(btree))
		return;

	snprintf(gi->subgraph, sizeof(gi->subgraph), "cluster_%s", gi->bname);
	fprintf(gi->f,
		"subgraph %s {\n"
		"label = \"%s\"\n",
		gi->subgraph, gi->bname);

	walk_btree(gi, btree, draw_leaf, data);

	fprintf(gi->f, "}\n");

	/* add external link for this tree */
	write_link(gi);
}

struct draw_data_ops {
	void (*draw_start)(struct graph_info *gi, struct btree *btree);
	void (*draw_data)(struct graph_info *gi, struct btree *btree,
			  block_t index, unsigned count);
	void (*draw_end)(struct graph_info *gi, struct btree *btree);
};

static void draw_subdata_start(struct graph_info *gi, struct btree *btree,
			       const char *postfix)
{
	fprintf(gi->f, "%s%s [\n", gi->lname, postfix);
}

static void draw_data_start(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"subgraph cluster_%s {\n"
		"label = \"%s\"\n",
		gi->lname, gi->lname);

	draw_subdata_start(gi, btree, "");
}

static void draw_data(struct graph_info *gi, struct btree *btree,
		      block_t index, unsigned count)
{
}

static void draw_subdata_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
		"shape = record\n"
		"];\n");
}

static void draw_data_end(struct graph_info *gi, struct btree *btree)
{
	draw_subdata_end(gi, btree);

	fprintf(gi->f, "}\n");
}

static void draw_bitmap_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->f, "label = \"{ dump of bitmap data");
}

static int bitmap_has_dirty;

static void draw_bitmap_data(struct graph_info *gi, struct btree *btree,
			     block_t index, unsigned count)
{
	struct sb *sb = btree->sb;
	struct inode *bitmap = sb->bitmap;
	void *data;

	for (unsigned i = 0; i < count; i++) {
		unsigned idx, size = sb->blocksize * 8;
		struct buffer_head *buffer;

		/* bit offset from index 0 and bit 0 */
		block_t offset = (index + i) * size;

		fprintf(gi->f, " | index %llu:", (index + i));
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
				fprintf(gi->f, " %llu-%llu,", start, end);
			else
				fprintf(gi->f, " %llu,", start);

			if (idx >= size)
				break;
			idx = find_next_bit_le(data, size, idx + 1);
			if (idx >= size)
				break;
		}
		fprintf(gi->f, " \\l"); /* left align */

		if (buffer_dirty(buffer))
			bitmap_has_dirty = 1;
		blockput(buffer);
	}
}

static void draw_bitmap_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
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

static void draw_vtable_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->f, "label = \"version table\"\n");
}

struct draw_data_ops draw_vtable = {
	.draw_start	= draw_vtable_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static void draw_atable_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->f, "label = \"{ dump of atable");
}

static void __draw_dir_data(struct graph_info *gi, struct btree *btree,
			    struct buffer_head *buffer)
{
	struct sb *sb = btree->sb;
	tux_dirent *entry = bufdata(buffer);
	tux_dirent *limit = (void *)entry + sb->blocksize;

	while (entry < limit) {
		fprintf(gi->f,
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
				fprintf(gi->f, " | ...");

			fprintf(gi->f,
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
			fprintf(gi->f,
				" | where 0x%08llx (atom %u)",
				be64_to_cpup(ptr), atom);

		}

		ptr++;
	}
}

static void draw_atable_data(struct graph_info *gi, struct btree *btree,
			     block_t index, unsigned count)
{
	static int start_atomref = 1, start_unatom = 1;

	struct sb *sb = btree->sb;
	struct buffer_head *buffer, *hi_buf;

	for (unsigned i = 0; i < count; i++) {
		buffer = blockread(mapping(sb->atable), index + i);
		assert(buffer);

		if (index < sb->atomref_base) {
			/* atom name table */
			__draw_dir_data(gi, btree, buffer);
		} else if (index < sb->unatom_base) {
			/* atom refcount table */
			if (start_atomref) {
				start_atomref = 0;
				fprintf(gi->f, " }\"\n");
				draw_subdata_end(gi, btree);
				draw_subdata_start(gi, btree, "_atomref");
				fprintf(gi->f, "label = \"{ dump of atomref");
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
				fprintf(gi->f, " }\"\n");
				draw_subdata_end(gi, btree);
				draw_subdata_start(gi, btree, "_unatom");
				fprintf(gi->f, "label = \"{ dump of unatom");
			}

			draw_atable_unatom(gi, btree, buffer);
		}

next:
		blockput(buffer);
	}
}

static void draw_atable_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f, " }\"\n");
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
	fprintf(gi->f,
		"label = \"{ dump of directory");
}

static void draw_dir_data(struct graph_info *gi, struct btree *btree,
			  block_t index, unsigned count)
{
	struct buffer_head *buffer;

	for (unsigned i = 0; i < count; i++) {
		buffer = blockread(mapping(btree_inode(btree)), index + i);
		assert(buffer);

		__draw_dir_data(gi, btree, buffer);

		blockput(buffer);
	}
}

static void draw_dir_end(struct graph_info *gi, struct btree *btree)
{
	fprintf(gi->f,
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
	fprintf(gi->f, "label = \"file data\"\n");
}

struct draw_data_ops draw_file = {
	.draw_start	= draw_file_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static void draw_symlink_start(struct graph_info *gi, struct btree *btree)
{
	draw_data_start(gi, btree);
	fprintf(gi->f, "label = \"symlink data\"\n");
}

struct draw_data_ops draw_symlink = {
	.draw_start	= draw_symlink_start,
	.draw_data	= draw_data,
	.draw_end	= draw_data_end,
};

static void draw_dleaf_start(struct graph_info *gi, const char *dleaf_name,
			     struct buffer_head *buffer)
{
	block_t blocknr = buffer->index;

	fprintf(gi->f,
		"%s [\n"
		"label = \"{ <head> [%s] (blocknr %llu%s)",
		dleaf_name, gi->lname, blocknr,
		buffer_dirty(buffer) ? ", dirty" : "");
}

static void draw_dleaf_end(struct graph_info *gi, const char *dleaf_name,
			   struct buffer_head *buffer)
{
	fprintf(gi->f,
		" }\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");
}

static inline struct group *dleaf_groups_ptr(struct btree *btree,
					      struct dleaf *dleaf)
{
	return (void *)dleaf + btree->sb->blocksize;
}

static inline struct group *dleaf_group_ptr(struct group *groups, int gr)
{
	return groups - (gr + 1);
}

static inline struct entry *dleaf_entries(struct dleaf *leaf,
					   struct group *groups, int gr)
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

static inline struct diskextent *dleaf_extent(struct diskextent *extents,
					       int ex)
{
	return extents + ex;
}

static void draw_dleaf1(struct graph_info *gi, struct btree *btree,
			const char *dleaf_name, struct buffer_head *buffer,
			void *data)
{
	struct dleaf *leaf = bufdata(buffer);
	struct group *groups = dleaf_groups_ptr(btree, leaf);
	struct diskextent *extents;
	int gr;

	draw_dleaf_start(gi, dleaf_name, buffer);

	fprintf(gi->f,
		" | magic 0x%04x, free %u, used %u, groups %u",
		be16_to_cpu(leaf->magic), be16_to_cpu(leaf->free),
		be16_to_cpu(leaf->used), dleaf_groups(leaf));

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
					extent_block(extents[ex]),
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
				get_index(group, entry));
		}
	}

	/* draw groups */
	for (gr = dleaf_groups(leaf) - 1; gr >= 0; gr--) {
		struct group *group = dleaf_group_ptr(groups, gr);

		fprintf(gi->f,
			" | <gr%u> count %u, keyhi 0x%06x (group %u)",
			gr, group_count(group), group_keyhi(group), gr);
	}

	draw_dleaf_end(gi, dleaf_name, buffer);

	for (gr = 0; gr < dleaf_groups(leaf); gr++) {
		struct group *group = dleaf_group_ptr(groups, gr);
		/* write link: dleaf:group -> dleaf:entry */
		fprintf(gi->f,
			"%s:gr%u:w -> %s:gr%uent%u:w;\n",
			dleaf_name, gr,
			dleaf_name, gr, 0);
		for (int ent = 0; ent < group_count(group); ent++) {
			/* write link: dleaf:entry -> dleaf:extent */
			fprintf(gi->f,
				"%s:gr%uent%u:w -> %s:gr%uent%uex%u:w;\n",
				dleaf_name, gr, ent,
				dleaf_name, gr, ent, 0);
		}
	}

	/* Walk again for file data */
	struct graph_info *gi_data = data;
	struct draw_data_ops *draw_data_ops = gi_data->private;
	struct dwalk walk;
	if (dwalk_probe(leaf, btree->sb->blocksize, &walk, 0)) {
		do {
			block_t index = dwalk_index(&walk);
			unsigned count = dwalk_count(&walk);
			draw_data_ops->draw_data(gi_data, btree, index, count);
		} while (dwalk_next(&walk));
	}
}

static void draw_dleaf2(struct graph_info *gi, struct btree *btree,
			const char *dleaf_name, struct buffer_head *buffer,
			void *data)
{
	struct graph_info *gi_data = data;
	struct draw_data_ops *draw_data_ops = gi_data->private;
	struct dleaf2 *leaf = bufdata(buffer);
	struct diskextent2 *dex, *dex_limit;
	struct extent prev = { .logical = TUXKEY_LIMIT, };

	draw_dleaf_start(gi, dleaf_name, buffer);

	fprintf(gi->f,
		" | magic 0x%04x, count %u",
		be16_to_cpu(leaf->magic), be16_to_cpu(leaf->count));

	dex = leaf->table;
	dex_limit = dex + be16_to_cpu(leaf->count);
	while (dex < dex_limit) {
		struct extent ex;
		get_extent(dex, &ex);

		if (prev.logical != TUXKEY_LIMIT) {
			unsigned count = ex.logical - prev.logical;
			fprintf(gi->f, " (count %u)", count);

			if (prev.physical) {
				/* Draw file data */
				draw_data_ops->draw_data(gi_data, btree,
							 prev.logical, count);
			}
		}

		fprintf(gi->f,
			" | verhi 0x%04x, logical %llu,"
			" verlo 0x%04x, physical %llu",
			ex.version >> VER_BITS, ex.logical,
			ex.version & VER_MASK, ex.physical);

		if (dex == dex_limit - 1)
			fprintf(gi->f, " (sentinel)");

		prev = ex;
		dex++;
	}

	draw_dleaf_end(gi, dleaf_name, buffer);
}

static void draw_dleaf(struct graph_info *gi, struct btree *btree,
		       struct buffer_head *buffer, void *data)
{
	struct dleaf *leaf = bufdata(buffer);
	block_t blocknr = buffer->index;
	char dleaf_name[32];

	if (!verbose && (drawn & DRAWN_DLEAF))
		return;
	drawn |= DRAWN_DLEAF;

	snprintf(dleaf_name, sizeof(dleaf_name), "volmap_%llu", blocknr);

	if (leaf->magic == cpu_to_be16(TUX3_MAGIC_DLEAF))
		draw_dleaf1(gi, btree, dleaf_name, buffer, data);
	else
		draw_dleaf2(gi, btree, dleaf_name, buffer, data);

	/* write link: dleaf -> file data */
	add_link(gi, "%s:s -> %s [ltail=%s, lhead=cluster_%s];\n",
		 dleaf_name, gi->filedata, gi->subgraph, gi->filedata);
}

typedef void (*draw_ileaf_attr_t)(struct graph_info *, struct btree *,
				  inum_t, void *, u16);

static inline u16 ileaf_attr_size(__be16 *dict, int at)
{
	int size = __atdict(dict, at + 1) - atdict(dict, at);
	assert(size >= 0);
	return size;
}

static void draw_ileaf_attr(struct graph_info *gi, struct btree *btree,
			    inum_t inum, void *attrs, u16 size)
{
	struct sb *sb = btree->sb;
	struct inode *inode = rapid_open_inode(sb, NULL, 0);

	/* Check there is orphaned inode */
	struct inode *cache_inode = tux3_ilookup(sb, inum);
	int orphan = 0;
	if (cache_inode) {
		orphan = !list_empty(&cache_inode->orphan_list);
		iput(cache_inode);
	}

	iattr_ops.decode(btree, inode, attrs, size);

	fprintf(gi->f,
		"%s"
		"attrs (ino %llu, size %u, block %llu, depth %d%s)"
		"%s",
		orphan ? "<font color=\"blue\">" : "",
		inum, size,
		inode->btree.root.block,
		inode->btree.root.depth,
		orphan ? ", orphan" : "",
		orphan ? "</font>" : "");

	free_xcache(inode);
	free_map(inode->map);
}

static void __draw_ileaf(struct graph_info *gi, struct btree *btree,
			 struct buffer_head *buffer,
			 draw_ileaf_attr_t draw_ileaf_attr)
{
	struct ileaf *ileaf = bufdata(buffer);
	__be16 *dict = ileaf_dict(btree, ileaf);
	block_t blocknr = buffer->index;
	int at;

	fprintf(gi->f,
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
		buffer_dirty(buffer) ? ", dirty" : "",
		be16_to_cpu(ileaf->magic), icount(ileaf), ibase(ileaf));

	/* draw inode attributes */
	u16 offset = 0, limit, size;
	for (at = 0; at < icount(ileaf); at++) {
		limit =__atdict(dict, at + 1);
		if (offset >= limit)
			continue;
		size = limit - offset;

		inum_t inum = ibase(ileaf) + at;
		void *attrs = ileaf->table + offset;

		offset = limit;

		fprintf(gi->f,
			"  <tr>\n"
			"    <td port=\"a%d\">",
			at);

		draw_ileaf_attr(gi, btree, inum, attrs, size);

		fprintf(gi->f,
			"</td>\n"
			"  </tr>\n");
	}
	fprintf(gi->f,
		"  <tr>\n"
		"   <td>.....</td>\n"
		"  </tr>\n");

	/* draw offset part */
	for (at = icount(ileaf) - 1; at >= 0; at--) {
		fprintf(gi->f,
			"  <tr>\n"
			"   <td port=\"o%d\">"
			"limit %u (offset %u, size %u, ino %llu)</td>\n"
			"  </tr>\n",
			at, atdict(dict, at + 1), atdict(dict, at),
			ileaf_attr_size(dict, at), ibase(ileaf) + at);
	}

	fprintf(gi->f,
		"</table>>\n"
		"shape = plaintext\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");

	/* draw allows from offset to attributes */
	for (at = 0; at < icount(ileaf); at++) {
		if (!ileaf_attr_size(dict, at))
			continue;

		/* write link: ileaf offset -> ileaf attrs */
		fprintf(gi->f,
			"volmap_%llu:o%d:w -> volmap_%llu:a%d:w;\n",
			blocknr, at,
			blocknr, at);
	}
}

static struct {
	const char *name;
	struct draw_data_ops *info;
}  dtree_types[] = {
	[TUX_BITMAP_INO] =  {
		.name = "bitmap",
		.info = &draw_bitmap,
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
struct draw_data_ops *dtree_funcs[S_IFMT >> S_SHIFT] = {
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

static void draw_ileaf(struct graph_info *gi, struct btree *btree,
		       struct buffer_head *buffer, void *data)
{
	struct ileaf *ileaf = bufdata(buffer);
	__be16 *dict = ileaf_dict(btree, ileaf);
	block_t blocknr = buffer->index;
	int at;

	if (!verbose && (drawn & DRAWN_ILEAF))
		return;
	drawn |= DRAWN_ILEAF;

	__draw_ileaf(gi, btree, buffer, draw_ileaf_attr);

	/* draw inode's dtree */
	for (at = 0; at < icount(ileaf); at++) {
		u16 size = ileaf_attr_size(dict, at);
		if (!size)
			continue;

		inum_t inum = ibase(ileaf) + at;
		struct inode *inode = tux3_iget(btree->sb, inum);
		if (IS_ERR(inode))
			error("inode couldn't get: inum %Lu", inum);

		if (!has_root(&inode->btree))
			goto out_iput;

		struct draw_data_ops *draw_data_ops;
		char name[64];
		int special_inode;
		if (inum < ARRAY_SIZE(dtree_types) && dtree_types[inum].name) {
			sprintf(name, "%s_dtree", dtree_types[inum].name);
			draw_data_ops = dtree_types[inum].info;
			special_inode = 1;
		} else {
			int file_type = (inode->i_mode & S_IFMT) >> S_SHIFT;
			sprintf(name, "ino%llu_dtree", inum);
			draw_data_ops = dtree_funcs[file_type];
			special_inode = 0;
		}
		assert(draw_data_ops);

		/* write link: ileaf -> dtree root bnode */
		add_link(gi, "volmap_%llu:a%d:e -> volmap_%llu:n;\n",
			 blocknr, at,
			 inode->btree.root.block);

		if (!special_inode) {
			if (!verbose && (drawn & DRAWN_DTREE)) {
				iput(inode);
				continue;
			}
			drawn |= DRAWN_DTREE;
		}

		/* for draw dtree */
		struct dtree_info *dinfo;
		dinfo = alloc_tmpfile();
		struct graph_info ginfo_dtree = {
			.f = dinfo->f,
			.bname = name,
			.lname = "dleaf",
			.link_head = LIST_HEAD_INIT(ginfo_dtree.link_head),
		};
		snprintf(ginfo_dtree.filedata, sizeof(ginfo_dtree.filedata),
			 "%s_data", name);

		/* for draw file data */
		dinfo = alloc_tmpfile();
		struct graph_info ginfo_data = {
			.f = dinfo->f,
			.bname = ginfo_dtree.filedata,
			.lname = ginfo_dtree.filedata,
			.link_head = LIST_HEAD_INIT(ginfo_data.link_head),
			.private = draw_data_ops,
		};

		draw_data_ops->draw_start(&ginfo_data, btree);

		draw_btree(&ginfo_dtree, &inode->btree, draw_dleaf,
			   &ginfo_data);

		draw_data_ops->draw_end(&ginfo_data, btree);

		/* draw at least one dleaf */
		drawn &= ~DRAWN_DLEAF;
out_iput:
		iput(inode);
	}
}

static void draw_oleaf_attr(struct graph_info *gi, struct btree *btree,
			    inum_t inum, void *attrs, u16 size)
{
	fprintf(gi->f, "attrs (ino %llu, size %u)", inum, size);
}

static void draw_oleaf(struct graph_info *gi, struct btree *btree,
		       struct buffer_head *buffer, void *data)
{
	if (!verbose && (drawn & DRAWN_OLEAF))
		return;
	drawn |= DRAWN_OLEAF;

	__draw_ileaf(gi, btree, buffer, draw_oleaf_attr);
}

static void draw_log(struct graph_info *gi, struct sb *sb,
		     struct buffer_head *buffer)
{
	static const char *log_name[] = {
#define X(x)	[x] = #x
		X(LOG_BALLOC),
		X(LOG_BFREE),
		X(LOG_BFREE_ON_ROLLUP),
		X(LOG_BFREE_RELOG),
		X(LOG_LEAF_REDIRECT),
		X(LOG_LEAF_FREE),
		X(LOG_BNODE_REDIRECT),
		X(LOG_BNODE_ROOT),
		X(LOG_BNODE_SPLIT),
		X(LOG_BNODE_ADD),
		X(LOG_BNODE_UPDATE),
		X(LOG_BNODE_MERGE),
		X(LOG_BNODE_DEL),
		X(LOG_BNODE_ADJUST),
		X(LOG_BNODE_FREE),
		X(LOG_ORPHAN_ADD),
		X(LOG_ORPHAN_DEL),
		X(LOG_FREEBLOCKS),
		X(LOG_ROLLUP),
		X(LOG_DELTA),
#undef X
	};
	/* Check whether array is uptodate */
	BUILD_BUG_ON(ARRAY_SIZE(log_name) != LOG_TYPES);

	struct logblock *log = bufdata(buffer);
	unsigned char *data = log->data;

	fprintf(gi->f,
		"logchain_%llu [\n"
		"label = \"{ <logchain_%llu> [log] (blocknr %llu%s)"
		" | <f0> magic 0x%04x, bytes %u, logchain %llu",
		buffer->index, buffer->index, buffer->index,
		buffer_dirty(buffer) ? ", dirty" : "",
		be16_to_cpu(log->magic), be16_to_cpu(log->bytes),
		be64_to_cpu(log->logchain));

	while (data < log->data + be16_to_cpu(log->bytes)) {
		unsigned char code = *data++;

		fprintf(gi->f, " | [%s] ", log_name[code]);

		switch (code) {
		case LOG_BALLOC:
		case LOG_BFREE:
		case LOG_BFREE_ON_ROLLUP:
		case LOG_BFREE_RELOG: {
			u32 count;
			u64 block;
			data = decode32(data, &count);
			data = decode48(data, &block);
			fprintf(gi->f, "count %u, block %llu ",
				count, block);
			break;
		}
		case LOG_LEAF_REDIRECT:
		case LOG_BNODE_REDIRECT: {
			u64 old, new;
			data = decode48(data, &old);
			data = decode48(data, &new);
			fprintf(gi->f, "old %llu, new %llu ",
				old, new);
			break;
		}
		case LOG_LEAF_FREE:
		case LOG_BNODE_FREE: {
			u64 block;
			data = decode48(data, &block);
			fprintf(gi->f, "%s %llu ",
				code == LOG_LEAF_FREE ? "leaf" : "bnode",
				block);
			break;
		}
		case LOG_BNODE_ROOT: {
			u64 root, left, right, rkey;
			unsigned count = *data++;
			data = decode48(data, &root);
			data = decode48(data, &left);
			data = decode48(data, &right);
			data = decode48(data, &rkey);
			fprintf(gi->f,
				"count %u, root %llu, left %llu, right %llu, "
				"right key %llu ",
				count, root, left, right, rkey);
			break;
		}
		case LOG_BNODE_SPLIT: {
			u64 src, dest;
			unsigned pos;
			data = decode16(data, &pos);
			data = decode48(data, &src);
			data = decode48(data, &dest);
			fprintf(gi->f, "pos %u, src %llu, dest %llu ",
				pos, src, dest);
			break;
		}
		case LOG_BNODE_ADD:
		case LOG_BNODE_UPDATE: {
			u64 parent, child, key;
			data = decode48(data, &parent);
			data = decode48(data, &child);
			data = decode48(data, &key);
			fprintf(gi->f, "parent %llu, child %llu, key %llu ",
				parent, child, key);
			break;
		}
		case LOG_BNODE_MERGE:
		{
			u64 src, dst;
			data = decode48(data, &src);
			data = decode48(data, &dst);
			fprintf(gi->f, "src %llu, dst %llu ", src, dst);
			break;
		}
		case LOG_BNODE_DEL:
		{
			unsigned count;
			u64 bnode, key;
			data = decode16(data, &count);
			data = decode48(data, &bnode);
			data = decode48(data, &key);
			fprintf(gi->f, "count %u, bnode %llu, key %llu ",
				count, bnode, key);
			break;
		}
		case LOG_BNODE_ADJUST:
		{
			u64 node, from, to;
			data = decode48(data, &node);
			data = decode48(data, &from);
			data = decode48(data, &to);
			fprintf(gi->f, "node %llu, from %llu, to %llu ",
				node, from, to);
			break;
		}
		case LOG_ORPHAN_ADD:
		case LOG_ORPHAN_DEL: {
			unsigned version;
			u64 inum;
			data = decode16(data, &version);
			data = decode48(data, &inum);
			fprintf(gi->f, "version %x, inum %llu ",
				version, inum);
			break;
		}
		case LOG_FREEBLOCKS: {
			u64 freeblocks;
			data = decode48(data, &freeblocks);
			fprintf(gi->f, "freeblocks %llu ", freeblocks);
			break;
		}
		case LOG_ROLLUP:
		case LOG_DELTA:
			break;
		default:
			fprintf(stderr, "Unknown log code 0x%x!\n", code);
			assert(0);
			break;
		}
	}
	fprintf(gi->f,
		"}\"\n"
		"shape = record\n"
		"%s"
		"];\n",
		buffer_dirty(buffer) ? "color = red\n" : "");
}

static void draw_logchain(struct graph_info *gi, struct sb *sb)
{
	struct buffer_head *buffer;
	block_t nextchain;
	unsigned logcount;

	fprintf(gi->f,
		"subgraph cluster_logchain {\n"
		"label = \"logchain\"\n");

	nextchain = be64_to_cpu(sb->super.logchain);
	logcount = be32_to_cpu(sb->super.logcount);
	while (logcount > 0) {
		buffer = vol_bread(sb, nextchain);
		assert(buffer);
		struct logblock *log = bufdata(buffer);
		assert(log->magic == cpu_to_be16(TUX3_MAGIC_LOG));
		draw_log(gi, sb, buffer);
		logcount--;
		if (logcount) {
			/* write link: logblock -> logblock */
			fprintf(gi->f,
				"logchain_%llu:f0:e -> logchain_%llu:n;\n",
				nextchain, be64_to_cpu(log->logchain));
		}
		nextchain = be64_to_cpu(log->logchain);
		blockput(buffer);
	}

	fprintf(gi->f,
		"}\n\n");
}

static void draw_sb(struct graph_info *gi, struct sb *sb)
{
	struct disksuper *txsb = &sb->super;

	fprintf(gi->f,
		"subgraph cluster_disksuper {\n"
		"label = \"disksuper\"\n"
		"tux3_sb [\n"
		"label = \"{ [disksuper] (blocknr %llu, freeblocks %llu)"
		" | magic %.4s, 0x%02x, 0x%02x, 0x%02x, 0x%02x"
		" | birthdate %llu | flags 0x%016llx"
		" | <iroot0> iroot 0x%016llx (depth %u, block %llu)"
		" | <oroot0> oroot 0x%016llx (depth %u, block %llu)"
		" | blockbits %u (size %u) | volblocks %llu"
#ifndef ATOMIC
		" | freeblocks %llu"
#endif
		" | nextalloc %llu"
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
		itable_btree(sb)->root.depth, itable_btree(sb)->root.block,
		be64_to_cpu(txsb->oroot),
		otable_btree(sb)->root.depth, otable_btree(sb)->root.block,
		sb->blockbits, sb->blocksize,
		be64_to_cpu(txsb->volblocks),
#ifndef ATOMIC
		be64_to_cpu(txsb->freeblocks),
#endif
		be64_to_cpu(txsb->nextalloc),
		be64_to_cpu(txsb->atomdictsize),
		be32_to_cpu(txsb->freeatom), be32_to_cpu(txsb->atomgen),
		be64_to_cpu(txsb->logchain), be64_to_cpu(txsb->logchain),
		be32_to_cpu(txsb->logcount));

	/* write link: sb -> itable root */
	fprintf(gi->f, "tux3_sb:iroot0:e -> volmap_%llu:n;\n\n",
		itable_btree(sb)->root.block);
	/* write link: sb -> otable root */
	fprintf(gi->f, "tux3_sb:oroot0:e -> volmap_%llu:n;\n\n",
		otable_btree(sb)->root.block);
	/* write link: sb -> logchain */
	fprintf(gi->f, "tux3_sb:logchain_%llu:e -> logchain_%llu:n;\n\n",
		be64_to_cpu(txsb->logchain), be64_to_cpu(txsb->logchain));
}

static void usage(void)
{
	printf("tux3  [-h|--help] [-v|--verbose] [-b|--blocksize=<size>] <volume>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	const char *volname = NULL;
	int ret = 0;

	while (1) {
		int c, optindex = 0;
		c = getopt_long(argc, argv, "b:vh", long_options, &optindex);
		if (c == -1)
			break;
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			goto usage;
		}
	}

	if (argc - optind < 1)
		goto usage;

	/* open volume, create superblock */
	volname = argv[optind++];
	int fd = open(volname, O_RDONLY);
	if (fd < 0)
		goto eek;

	/* dev->bits is still unknown. Note, some structure can't use yet. */
	struct dev *dev = &(struct dev){ .fd = fd };
	struct sb *sb = rapid_sb(dev);
	if ((errno = -load_sb(sb)))
		goto eek;
	dev->bits = sb->blockbits;
	init_buffers(dev, 1 << 20, 2);

	struct replay *rp = tux3_init_fs(sb);
	if (IS_ERR(rp)) {
		errno = -PTR_ERR(rp);
		goto eek;
	}

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
		.bname = itable_name,
		.lname = "ileaf",
		.link_head = LIST_HEAD_INIT(ginfo.link_head),
	};
	draw_sb(&ginfo, sb);
	draw_logchain(&ginfo, sb);
	draw_btree(&ginfo, itable_btree(sb), draw_ileaf, NULL);

	ginfo = (struct graph_info){
		.f = file,
		.bname = otable_name,
		.lname = "oleaf",
		.link_head = LIST_HEAD_INIT(ginfo.link_head),
	};
	draw_btree(&ginfo, otable_btree(sb), draw_oleaf, NULL);

	merge_tmpfiles(&ginfo);

	fprintf(ginfo.f, "}\n");
	fclose(ginfo.f);

	if ((errno = -replay_stage3(rp, 0)))
		goto eek;

	put_super(sb);

out:
	return ret;

eek:
	fprintf(stderr, "%s!\n", strerror(errno));
	ret = 1;
	goto out;
usage:
	usage();
	ret = 1;
	goto out;
}
