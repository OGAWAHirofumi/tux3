#ifndef TUX3_DLEAF_H
#define TUX3_DLEAF_H

/* version:10, count:6, block:48 */
struct diskextent { be_u64 block_count_version; };
#define MAX_GROUP_ENTRIES 255
/* count:8, keyhi:24 */
struct group { be_u32 count_and_keyhi; };
/* limit:8, keylo:24 */
struct entry { be_u32 limit_and_keylo; };
struct dleaf { be_u16 magic, groups, free, used; struct diskextent table[]; };

/* Maximum size of one extent on dleaf. */
#define DLEAF_MAX_EXTENT_SIZE \
	(sizeof(struct group)+sizeof(struct entry)+sizeof(struct diskextent))

struct dwalk {
	struct dleaf *leaf;
	struct group *group, *gstop, *gdict;
	struct entry *entry, *estop;
	struct diskextent *exbase, *extent, *exstop;
	struct {
		struct group group;
		struct entry entry;
		int used, free, groups;
	} mock;
};

/* group wrappers */

static inline struct group make_group(tuxkey_t keyhi, unsigned count)
{
	return (struct group){ to_be_u32(keyhi | (count << 24)) };
}

static inline unsigned group_keyhi(struct group *group)
{
	return from_be_u32(*(be_u32 *)group) & 0xffffff;
}

static inline unsigned group_count(struct group *group)
{
	return *(unsigned char *)group;
}

static inline void set_group_count(struct group *group, int n)
{
	*(unsigned char *)group = n;
}

static inline void inc_group_count(struct group *group, int n)
{
	*(unsigned char *)group += n;
}

/* entry wrappers */

static inline struct entry make_entry(tuxkey_t keylo, unsigned limit)
{
	return (struct entry){ to_be_u32(keylo | (limit << 24)) };
}

static inline unsigned entry_keylo(struct entry *entry)
{
	return from_be_u32(*(be_u32 *)entry) & ~(-1 << 24);
}

static inline unsigned entry_limit(struct entry *entry)
{
	return *(unsigned char *)entry;
}

static inline void inc_entry_limit(struct entry *entry, int n)
{
	*(unsigned char *)entry += n;
}

/* extent wrappers */

static inline struct diskextent make_extent(block_t block, unsigned count)
{
	assert(block < (1ULL << 48) && count - 1 < (1 << 6));
	return (struct diskextent){ to_be_u64(((u64)(count - 1) << 48) | block) };
}

static inline block_t extent_block(struct diskextent extent)
{
	return from_be_u64(*(be_u64 *)&extent) & ~(-1LL << 48);
}

static inline unsigned extent_count(struct diskextent extent)
{
	return ((from_be_u64(*(be_u64 *)&extent) >> 48) & 0x3f) + 1;
}

static inline unsigned extent_version(struct diskextent extent)
{
	return from_be_u64(*(be_u64 *)&extent) >> 54;
}

/* dleaf wrappers */

static inline unsigned dleaf_groups(struct dleaf *leaf)
{
	return from_be_u16(leaf->groups);
}

static inline void set_dleaf_groups(struct dleaf *leaf, int n)
{
	leaf->groups = to_be_u16(n);
}

static inline void inc_dleaf_groups(struct dleaf *leaf, int n)
{
	leaf->groups = to_be_u16(from_be_u16(leaf->groups) + n);
}

int dleaf_init(struct btree *btree, void *leaf);
unsigned dleaf_free(struct btree *btree, void *leaf);
void dleaf_dump(struct btree *btree, void *vleaf);
int dleaf_merge(struct btree *btree, void *vinto, void *vfrom);
extern struct btree_ops dtree1_ops;

void dwalk_redirect(struct dwalk *walk, struct dleaf *src, struct dleaf *dst);
int dwalk_end(struct dwalk *walk);
block_t dwalk_block(struct dwalk *walk);
unsigned dwalk_count(struct dwalk *walk);
tuxkey_t dwalk_index(struct dwalk *walk);
int dwalk_next(struct dwalk *walk);
int dwalk_back(struct dwalk *walk);
int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key);
int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct diskextent extent);
void dwalk_copy(struct dwalk *walk, struct dleaf *dest);
void dwalk_chop(struct dwalk *walk);
int dwalk_add(struct dwalk *walk, tuxkey_t index, struct diskextent extent);
#endif /* !TUX3_DLEAF_H */
