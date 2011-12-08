TOPDIR = $(CURDIR)

ARCH	= $(shell uname -m)

CC	= gcc

ifeq ($(ARCH),x86_64)
CFLAGS	+= -m64
else
CFLAGS	+= -m32
endif

CFLAGS	+= -std=gnu99 -Wall -g -rdynamic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS	+= -I$(TOPDIR)
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

INSTALL	= install

TESTDIR	= $(TOPDIR)
OWNER	= root
GROUP	= root

DISTDIR	=
PREFIX	= /usr/local
SBINDIR	= $(PREFIX)/sbin
LIBEXECDIR = $(PREFIX)/libexec/tux3

TUX3_BIN	= tux3 #tux3graph
ifeq ($(shell pkg-config fuse && echo found), found)
	FUSE_BIN = tux3fuse
endif
TEST_BIN	= tests/balloc tests/btree tests/buffer tests/commit \
	tests/dir tests/dleaf tests/filemap tests/iattr tests/ileaf \
	tests/inode tests/xattr
ALL_BIN		= $(TEST_BIN) $(TUX3_BIN) $(FUSE_BIN)

COMMON_OBJS	= utility.o writeback.o
OBJS		= buffer.o diskio.o dir.o tux3.o tux3graph.o
KERN_OBJS	= kernel/balloc.o kernel/btree.o kernel/commit.o \
	kernel/dleaf.o kernel/iattr.o kernel/ileaf.o kernel/log.o \
	kernel/replay.o kernel/xattr.o
FUSE_OBJS	= tux3fuse.o
TEST_OBJS	= tests/balloc.o tests/btree.o tests/buffer.o tests/commit.o \
	tests/dleaf.o tests/filemap.o tests/iattr.o tests/ileaf.o tests/xattr.o
ALL_OBJS	= $(COMMON_OBJS) $(OBJS) $(KERN_OBJS) $(FUSE_OBJS) $(TEST_OBJS)

.PHONY: tests
all: $(ALL_BIN)

# objects dependency
tux3: $(COMMON_OBJS) $(KERN_OBJS) dir.o filemap.o inode.o super.o tux3.o
tux3graph: $(COMMON_OBJS) tux3graph.o
tests/balloc: $(COMMON_OBJS) tests/balloc.o
tests/btree: $(COMMON_OBJS) kernel/btree.o kernel/log.o tests/btree.o
tests/buffer: buffer.o diskio.o tests/buffer.o
tests/commit: $(COMMON_OBJS) $(KERN_OBJS) dir.o filemap.o inode.o super.o \
	 tests/commit.o
tests/dir: $(COMMON_OBJS) dir.o tests/dir.o
tests/dleaf: $(COMMON_OBJS) tests/dleaf.o
tests/filemap: $(COMMON_OBJS) $(KERN_OBJS) dir.o tests/filemap.o
tests/iattr: $(COMMON_OBJS) tests/iattr.o
tests/ileaf: $(COMMON_OBJS) kernel/iattr.o dir.o kernel/xattr.o tests/ileaf.o
tests/inode: $(COMMON_OBJS) $(KERN_OBJS) dir.o filemap.o super.o tests/inode.o
tests/xattr: $(COMMON_OBJS) dir.o kernel/balloc.o kernel/dleaf.o kernel/iattr.o kernel/log.o tests/xattr.o

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
$(COMMON_OBJS) $(OBJS) $(TEST_OBJS): %.o: %.c $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) -c $<
endif

# use -include tux3user.h to compile kernel/* without any change
$(KERN_OBJS): %.o: %.c $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) -include tux3user.h -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) -include tux3user.h $(CHECKFLAGS) -c $<
endif


$(TEST_BIN) $(TUX3_BIN):
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(FUSE_BIN): $(COMMON_OBJS) $(KERN_OBJS) $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) $(LDFLAGS) $$(pkg-config --cflags fuse) $(COMMON_OBJS) $(KERN_OBJS) filemap.o dir.o inode.o tux3fuse.c -lfuse -o tux3fuse
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

clean:
	rm -f $(ALL_BIN) *.o tests/*.o kernel/*.o
	rm -f a.out tests/foodev foodev $(TESTDIR)/testdev

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
makefs mkfs: tux3
	dd if=/dev/zero of=$(TESTDIR)/testdev bs=1 count=1 seek=1M
	./tux3 mkfs $(TESTDIR)/testdev
	mkdir -p $(TESTDIR)/test
	if [[ ! -f /etc/fuse.conf ]]; then sudo sh -c "echo user_allow_other >/etc/fuse.conf"; fi

# tests rules
tests: $(TEST_BIN)
	make -C tests

testfs testfuse: makefs
	./tux3fuse $(TESTDIR)/testdev $(TESTDIR)/test -o allow_other

debug defuse: tux3fuse
	sudo ./tux3fuse $(TESTDIR)/testdev $(TESTDIR)/test -o allow_other -f

untest:
	sudo umount $(TESTDIR)/test || true
	rmdir $(TESTDIR)/test

unbork:
	sudo umount -l $(TESTDIR)/test
