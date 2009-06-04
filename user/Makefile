ARCH = $(shell uname -m)
CC = gcc
ifeq ($(ARCH),x86_64)
CFLAGS  += -m64
else
CFLAGS  += -m32
endif

CFLAGS += -std=gnu99 -Wall -g -rdynamic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers
CFLAGS += $(UCFLAGS)

LDFLAGS =

CHECKER = sparse
CHECKFLAGS = -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise -Wno-transparent-union
CHECKFLAGS += -Wno-decl -Wno-declaration-after-statement

VG=valgrind --error-exitcode=200 --leak-check=full
INSTALL = install

TESTDIR = .
OWNER = root
GROUP = root

DISTDIR =
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
LIBEXECDIR = $(PREFIX)/libexec/tux3

ifeq ($(shell pkg-config fuse && echo found), found)
	fusebin = tux3fuse
endif

testbin = buffer balloc dleaf ileaf iattr xattr btree dir filemap inode commit
tux3bin = tux3 tux3graph
binaries = $(testbin) $(tux3bin) $(fusebin)

tuxdeps		= Makefile trace.h kernel/trace.h
diskiodeps	= diskio.c diskio.h
bufferdeps	= buffer.c buffer.h diskio.h err.h list.h
utilitydeps	= $(bufferdeps) $(diskiodeps) utility.c
basedeps	= $(tuxdeps) err.h list.h buffer.h diskio.h tux3.h \
	kernel/tux3.h hexdump.c lockdebug.h
ballocdeps	= kernel/balloc.c
btreedeps	= balloc-dummy.c kernel/btree.c
commitdeps	= $(inodedeps)
dirdeps		= dir.c kernel/dir.c
dleafdeps	= balloc-dummy.c kernel/dleaf.c
filemapdeps	= $(dirdeps) kernel/log.c kernel/xattr.c kernel/dleaf.c \
	kernel/btree.c kernel/iattr.c kernel/ileaf.c kernel/balloc.c \
	filemap.c kernel/filemap.c kernel/commit.c
iattrdeps	= btree-dummy.c kernel/iattr.c
xattrcommondeps	= $(dirdeps) btree-dummy.c kernel/iattr.c \
	kernel/xattr.c kernel/ileaf.c
ileafdeps	= balloc-dummy.c $(xattrcommondeps)
inodedeps	= $(filemapdeps) inode.c kernel/inode.c super.c
superdeps	= $(inodedeps) super.c kernel/super.c
writebackdeps	= writeback.c
xattrdeps	= kernel/balloc.c $(xattrcommondeps)

common-objs	= utility.o writeback.o

all: $(binaries)
tests: test_buffer test_balloc test_commit test_dleaf test_ileaf \
	test_btree test_dir test_iattr test_xattr test_filemap test_inode

bin: $(tux3bin) $(fusebin)
testbin: $(testbin)

# standalone and library
buffer.o: $(tuxdeps) $(bufferdeps)
diskio.o: $(tuxdeps) $(diskiodeps)
utility.o: $(tuxdeps) $(utilitydeps)
# standalone
balloc.o: $(basedeps) $(ballocdeps)
btree.o: $(basedeps) $(btreedeps)
commit.o: $(basedeps) $(commitdeps)
dir.o: $(basedeps) $(dirdeps)
dleaf.o: $(basedeps) $(dleafdeps)
filemap.o: $(basedeps) $(filemapdeps)
iattr.o: $(basedeps) $(iattrdeps)
ileaf.o: $(basedeps) $(ileafdeps)
inode.o: $(basedeps) $(inodedeps)
writeback.o: $(basedeps) $(writebackdeps)
xattr.o:$(basedeps) $(xattrdeps)
# programs
tux3.o:$(basedeps) $(superdeps)
tux3fuse.o:$(basedeps) $(superdeps)
tux3graph.o:$(basedeps) $(superdeps)

buffer: buffer.o diskio.o
dleaf: $(common-objs) dleaf.o
balloc: $(common-objs) balloc.o
ileaf: $(common-objs) ileaf.o
btree: $(common-objs) btree.o
dir: $(common-objs) dir.o
iattr: $(common-objs) iattr.o
xattr: $(common-objs) xattr.o
inode: $(common-objs) inode.o
filemap: $(common-objs) filemap.o
commit: $(common-objs) commit.o
tux3: $(common-objs) tux3.o
tux3graph: $(common-objs) tux3graph.o

.c.o:
	$(CC) $(CFLAGS) -Dbuild_$(<:.c=) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) -Dbuild_$(<:.c=) $(CHECKFLAGS) -c $<
endif

$(testbin) $(tux3bin):
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

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

tux3fuse: $(common-objs) tux3fuse.o
	$(CC) $(CFLAGS) $(LDFLAGS) $$(pkg-config --cflags fuse) $(common-objs) tux3fuse.c -lfuse -o tux3fuse
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

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

clean:
	rm -f $(binaries) *.o a.out foodev $(TESTDIR)/testdev
	rm -f kernel/*.o

distclean: clean
	rm -f *.orig kernel/*.orig

install: install-bin install-test

install-bin:
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(SBINDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(tux3bin) $(fusebin) $(DISTDIR)$(SBINDIR)

install-test: install-bin
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 -d $(DISTDIR)$(LIBEXECDIR)
	$(INSTALL) -c -o $(OWNER) -g $(GROUP) -m 755 $(testbin) $(DISTDIR)$(LIBEXECDIR)
