TOPDIR = $(CURDIR)

ARCH	= $(shell uname -m)

CC	= gcc
AR	= ar

ifeq ($(ARCH),x86_64)
CFLAGS	+= -m64
endif
ifeq ($(ARCH),i686)
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
# gcc checker (_FORTIFY_SOURCE requires optimize option >= 1)
# Rethink about this when optimization become default
#CFLAGS	+= -O1 -D_FORTIFY_SOURCE=2
# gcov
ifneq ($(GCOV),)
CFLAGS	+= --coverage
endif
# use LOCK_DEBUG
CFLAGS	+= -DLOCK_DEBUG=1
# use UNIFY_DEBUG
CFLAGS	+= -DUNIFY_DEBUG=1
# userland can't use async, so use TUX3_FLUSHER_SYNC
CFLAGS	+= -DTUX3_FLUSHER=TUX3_FLUSHER_SYNC
# user flags
CFLAGS	+= $(UCFLAGS)

LDFLAGS =
AFLAGS	= rcs

CHECKER	   = sparse
CHECKFLAGS = -gcc-base-dir $(shell $(CC) -print-file-name=)
# Add multiarch include if need (workaround for debian's multiarch)
CHECKFLAGS += $(shell if gcc -print-multiarch > /dev/null 2>&1; then \
		echo "-isystem /usr/include/`gcc -print-multiarch`"; fi)
CHECKFLAGS += -D__CHECKER__ -D__CHECK_ENDIAN__
CHECKFLAGS += -Wsparse-all -Wno-transparent-union
CHECKFLAGS += -Wno-declaration-after-statement
CHECKFLAGS += -Wno-decl
CHECKFLAGS += -Wno-ptr-subtraction-blows

INSTALL	= install

TESTDIR	= $(TOPDIR)
OWNER	= root
GROUP	= root

# lcov flags
GCOV_DIR = gcov
LCOV_FLAGS = --capture
GENHTML_FLAGS = --prefix $(abspath $(TOPDIR)/../) --show-details --legend
# lcov-1.10 or above, branch coverage is off by default, enable it
ifeq ($(shell lcov --help | grep -q -- --rc && echo has_rc), has_rc)
	LCOV_FLAGS += --rc lcov_branch_coverage=1
	GENHTML_FLAGS += --branch-coverage
endif

DISTDIR	=
PREFIX	= /usr/local
SBINDIR	= $(PREFIX)/sbin
LIBEXECDIR = $(PREFIX)/libexec/tux3

# binaries
TUX3_BIN	= tux3
ifeq ($(shell pkg-config fuse && echo found), found)
	FUSE_BIN = tux3fuse
endif
TEST_BIN	= tests/balloc tests/btree tests/buffer tests/commit \
	tests/dir tests/dleaf tests/filemap tests/iattr \
	tests/ileaf tests/inode tests/log tests/xattr
ALL_BIN		= $(TEST_BIN) $(TUX3_BIN) $(FUSE_BIN)

# libraries
LIBTUX3		= libtux3.a
LIBKLIB		= libklib/libklib.a
ALL_LIBS	= $(LIBTUX3) $(LIBKLIB)

# LIBTUX3 objects
USER_OBJS	= current_task.o dir.o filemap.o inode.o namei.o options.o \
	super.o utility.o writeback.o
KERN_OBJS	= kernel/balloc.o kernel/btree.o kernel/commit.o \
	kernel/dleaf.o kernel/iattr.o kernel/ileaf.o \
	kernel/log.o kernel/orphan.o kernel/replay.o kernel/xattr.o
TEST_LIB_OBJS	= tests/test.o

# LIBKLIB objects
LIBKLIB_OBJS	= libklib/find_next_bit.o libklib/fs.o libklib/list_sort.o \
	libklib/slab.o libklib/uidgid.o

# binary objects
OBJS		= tux3.o
FUSE_OBJS	= tux3fuse.o
TEST_OBJS	= tests/balloc.o tests/btree.o tests/buffer.o tests/commit.o \
	tests/dir.o tests/dleaf.o tests/filemap.o \
	tests/iattr.o tests/ileaf.o tests/inode.o tests/log.o \
	tests/xattr.o

# objects for common build rules
COMMON_OBJS	= $(USER_OBJS) $(TEST_LIB_OBJS) $(LIBKLIB_OBJS) $(OBJS) \
	$(TEST_OBJS)

ALL_OBJS	= $(USER_OBJS) $(KERN_OBJS) $(TEST_LIB_OBJS) $(LIBKLIB_OBJS) \
	$(OBJS) $(FUSE_OBJS) $(TEST_OBJS)
# directories includes objects
OBJS_DIRS := $(sort $(dir $(ALL_OBJS)))

.PHONY: tests
all: $(ALL_BIN)

# objects dependency
$(LIBTUX3): $(USER_OBJS) $(KERN_OBJS) $(TEST_LIB_OBJS)
$(LIBKLIB): $(LIBKLIB_OBJS)
tux3: tux3.o $(ALL_LIBS)
tests/balloc: tests/balloc.o $(ALL_LIBS)
tests/btree: tests/btree.o $(ALL_LIBS)
tests/buffer: tests/buffer.o $(ALL_LIBS)
tests/commit: tests/commit.o $(ALL_LIBS)
tests/dir: tests/dir.o $(ALL_LIBS)
tests/dleaf: tests/dleaf.o $(ALL_LIBS)
tests/filemap: tests/filemap.o $(ALL_LIBS)
tests/iattr: tests/iattr.o $(ALL_LIBS)
tests/ileaf: tests/ileaf.o $(ALL_LIBS)
tests/inode: tests/inode.o $(ALL_LIBS)
tests/log: tests/log.o $(ALL_LIBS)
tests/xattr: tests/xattr.o $(ALL_LIBS)

# dependency generation
DEPDIR	  := .deps
DEP_FILES := $(foreach f,$(ALL_OBJS),$(dir $f)$(DEPDIR)/$(notdir $f).d)
DEP_DIRS  := $(addsuffix $(DEPDIR),$(OBJS_DIRS))
MISSING_DEP_DIRS := $(filter-out $(wildcard $(DEP_DIRS)),$(DEP_DIRS))

$(DEP_DIRS):
	mkdir -p $@

DEP_FILE = $(dir $@)$(DEPDIR)/$(notdir $@).d
DEP_ARGS = -MF $(DEP_FILE) -MP -MMD
# Take advantage of gcc's on-the-fly dependency generation
# See <http://gcc.gnu.org/gcc-3.0/features.html>.
DEP_FILES_PRESENT := $(wildcard $(DEP_FILES))
-include $(DEP_FILES_PRESENT)

# common build rules
$(COMMON_OBJS): %.o: %.c $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CHECKFLAGS) $(CFLAGS) -c $<
endif

# use -include tux3user.h to compile kernel/* without any change
$(KERN_OBJS): %.o: %.c $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) -include tux3user.h -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CHECKFLAGS) $(CFLAGS) -include tux3user.h -c $<
endif

# build libraries rules
$(LIBTUX3) $(LIBKLIB):
	rm -f $@ && $(AR) $(AFLAGS) $@ $^

# build binaries rules
$(TEST_BIN) $(TUX3_BIN):
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(FUSE_BIN): tux3fuse.c $(ALL_LIBS) $(MISSING_DEP_DIRS)
	$(CC) $(DEP_ARGS) $(CFLAGS) $(LDFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c -lfuse -o tux3fuse $(ALL_LIBS)
ifeq ($(CHECK),1)
	$(CHECKER) $(CHECKFLAGS) $(CFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

clean:
	rm -f $(ALL_BIN) $(ALL_LIBS) $(ALL_OBJS)
	rm -f a.out $(TESTDIR)/testdev
	rm -f $(addsuffix *.gcda,$(OBJS_DIRS))
	rm -f $(addsuffix *.gcno,$(OBJS_DIRS))
	make -C tests clean

distclean: clean
	rm -f $(addsuffix *.orig,$(OBJS_DIRS))
	rm -rf $(DEP_DIRS)
	rm -rf $(GCOV_DIR)

install: install-bin install-test

install-bin: $(TUX3_BIN) $(FUSE_BIN)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(SBINDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(TUX3_BIN) $(FUSE_BIN) $(DISTDIR)$(SBINDIR)

install-test: install-bin $(TEST_BIN)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(LIBEXECDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(TEST_BIN) $(DISTDIR)$(LIBEXECDIR)

# tests rules
tests: $(TEST_BIN)
	make -C tests

# Use lcov to summarize gcov data
coverage:
	# NOTE: need to compile with GCOV=1
	[ -d $(GCOV_DIR) ] || mkdir $(GCOV_DIR)
	lcov $(LCOV_FLAGS) -b $(TOPDIR) -d $(TOPDIR) -o $(GCOV_DIR)/tux3.info
	genhtml $(GENHTML_FLAGS) -o $(GCOV_DIR) $(GCOV_DIR)/tux3.info

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
