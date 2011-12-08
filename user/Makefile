ARCH = $(shell uname -m)

CC	= gcc

ifeq ($(ARCH),x86_64)
CFLAGS	+= -m64
else
CFLAGS	+= -m32
endif

CFLAGS	+= -std=gnu99 -Wall -g -rdynamic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
# gcc warning options
CFLAGS	+= -Wall -Wextra -Werror
CFLAGS	+= -Wundef -Wstrict-prototypes -Werror-implicit-function-declaration
CFLAGS	+= -Wno-unused-parameter -Wno-sign-compare
CFLAGS	+= -Wno-missing-field-initializers
#CFLAGS += -Wp,-Wunused-macros
# gcc checker
CFLAGS	+= -D_FORTIFY_SOURCE=2
# user flags
CFLAGS	+= $(UCFLAGS)

LDFLAGS =

CHECKER	   = sparse
CHECKFLAGS = -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise -Wno-transparent-union
CHECKFLAGS += -Wno-decl -Wno-declaration-after-statement

VG	= valgrind --error-exitcode=200 --leak-check=full
INSTALL	= install

TESTDIR	= .
OWNER	= root
GROUP	= root

DISTDIR	=
PREFIX	= /usr/local
SBINDIR	= $(PREFIX)/sbin
LIBEXECDIR = $(PREFIX)/libexec/tux3

TUX3_BIN	= tux3 tux3graph
TEST_BIN	= buffer balloc dleaf ileaf iattr xattr btree dir filemap \
	inode commit
ifeq ($(shell pkg-config fuse && echo found), found)
	FUSE_BIN = tux3fuse
endif
ALL_BIN		= $(TEST_BIN) $(TUX3_BIN) $(FUSE_BIN)

COMMON_OBJS	= utility.o writeback.o
OBJS		= buffer.o diskio.o dleaf.o balloc.o ileaf.o btree.o dir.o \
	iattr.o xattr.o inode.o filemap.o commit.o tux3.o tux3graph.o
FUSE_OBJS	= tux3fuse.o
ALL_OBJS	= $(COMMON_OBJS) $(OBJS) $(FUSE_OBJS)

all: $(ALL_BIN)

# objects dependency
buffer: buffer.o diskio.o
dleaf: $(COMMON_OBJS) dleaf.o
balloc: $(COMMON_OBJS) balloc.o
ileaf: $(COMMON_OBJS) ileaf.o
btree: $(COMMON_OBJS) btree.o
dir: $(COMMON_OBJS) dir.o
iattr: $(COMMON_OBJS) iattr.o
xattr: $(COMMON_OBJS) xattr.o
inode: $(COMMON_OBJS) inode.o
filemap: $(COMMON_OBJS) filemap.o
commit: $(COMMON_OBJS) commit.o
tux3: $(COMMON_OBJS) tux3.o
tux3graph: $(COMMON_OBJS) tux3graph.o

# dependency generation
DEPDIR	  := .deps
DEP_FILES := $(foreach f,$(ALL_OBJS),$(dir $f)$(DEPDIR)/$(notdir $f).d)
DEP_DIRS  := $(addsuffix $(DEPDIR),$(sort $(dir $(ALL_OBJS))))
MISSING_DEP_DIRS := $(filter-out $(wildcard $(DEP_DIRS)),$(DEP_DIRS))

$(DEP_DIRS):
	mkdir -p $@

DEP_FILE = $(dir $@)$(DEPDIR)/$(notdir $@).d
DEP_ARGS = -MF $(DEP_FILE) -MP -MMD
# Take advantage of gcc's on-the-fly dependency generation
# See <http://gcc.gnu.org/gcc-3.0/features.html>.
DEP_FILES_PRESENT := $(wildcard $(DEP_FILES))
-include $(DEP_FILES_PRESENT)

# rules
$(COMMON_OBJS) $(OBJS): %.o: %.c $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) -Dbuild_$(<:.c=) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) -Dbuild_$(<:.c=) $(CHECKFLAGS) -c $<
endif

$(TEST_BIN) $(TUX3_BIN):
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(FUSE_BIN): $(COMMON_OBJS) $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) $(LDFLAGS) $$(pkg-config --cflags fuse) $(COMMON_OBJS) tux3fuse.c -lfuse -o tux3fuse
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

clean:
	rm -f $(ALL_BIN) *.o a.out foodev $(TESTDIR)/testdev
	rm -f kernel/*.o

distclean: clean
	rm -f *.orig kernel/*.orig
	rm -rf $(DEP_DIRS)

install: install-bin install-test

install-bin: $(TUX3_BIN) $(FUSE_BIN)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(SBINDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(TUX3_BIN) $(FUSE_BIN) $(DISTDIR)$(SBINDIR)

install-test: install-bin $(TEST_BIN)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(LIBEXECDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(TEST_BIN) $(DISTDIR)$(LIBEXECDIR)

# test rules
#.NOTPARALLEL: tests
# The "tests" run in order, otherwise those will output the result
# mixed.  But make seems to disable all in this Makefile. (FIXME: we
# should move tests to other directory to fix this, and keep clean
# source directory)

tests: test_buffer test_balloc test_commit test_dleaf test_ileaf \
	test_btree test_dir test_iattr test_xattr test_filemap test_inode

test_buffer: buffer
	$(VG) ./buffer

test_balloc: balloc
	$(VG) ./balloc

test_dleaf: dleaf
	$(VG) ./dleaf

test_ileaf: ileaf
	$(VG) ./ileaf

test_btree: btree
	$(VG) ./btree foodev

test_dir: dir
	$(VG) ./dir

test_iattr: iattr
	$(VG) ./iattr

test_xattr: xattr
	$(VG) ./xattr foodev

test_filemap: filemap
	$(VG) ./filemap foodev

test_inode: inode
	$(VG) ./inode foodev

test_commit: commit
	$(VG) ./commit foodev

makefs mkfs: tux3
	dd if=/dev/zero of=$(TESTDIR)/testdev bs=1 count=1 seek=1M
	./tux3 mkfs $(TESTDIR)/testdev
	mkdir -p $(TESTDIR)/test
	if [[ ! -f /etc/fuse.conf ]]; then sudo sh -c "echo user_allow_other >/etc/fuse.conf"; fi

testfs testfuse: makefs
	./tux3fuse $(TESTDIR)/testdev $(TESTDIR)/test -o allow_other

debug defuse: tux3fuse
	sudo ./tux3fuse $(TESTDIR)/testdev $(TESTDIR)/test -o allow_other -f

untest:
	sudo umount $(TESTDIR)/test || true
	rmdir $(TESTDIR)/test

unbork:
	sudo umount -l $(TESTDIR)/test
