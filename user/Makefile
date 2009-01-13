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

CHECKER = sparse
CHECKFLAGS = -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise -Wno-transparent-union
CHECKFLAGS += -Wno-decl -Wno-declaration-after-statement

VG=valgrind --error-exitcode=200 --leak-check=full

TESTDIR = .

testbin = buffer balloc dleaf ileaf iattr xattr btree dir filemap inode commit
binaries = $(testbin) tux3 tux3fuse tux3graph

ifeq ($(shell pkg-config fuse && echo found), found)
	binaries += tux3fuse
endif

tuxdeps		= Makefile trace.h kernel/trace.h
diskiodeps	= diskio.c diskio.h
bufferdeps	= buffer.c buffer.h diskio.h err.h list.h
vfsdeps		= $(bufferdeps) $(diskiodeps) vfs.c
basedeps	= $(tuxdeps) err.h list.h buffer.h diskio.h tux3.h \
	kernel/tux3.h hexdump.c
ballocdeps	= kernel/balloc.c
btreedeps	= balloc-dummy.c kernel/btree.c
commitdeps	= $(inodedeps)
dirdeps		= dir.c kernel/dir.c
dleafdeps	= balloc-dummy.c kernel/dleaf.c
filemapdeps	= $(dirdeps) kernel/log.c kernel/xattr.c kernel/dleaf.c \
	kernel/btree.c kernel/iattr.c kernel/ileaf.c kernel/balloc.c \
	filemap.c kernel/filemap.c
iattrdeps	= btree-dummy.c kernel/iattr.c
xattrcommondeps	= $(dirdeps) btree-dummy.c kernel/iattr.c \
	kernel/xattr.c kernel/ileaf.c
ileafdeps	= balloc-dummy.c $(xattrcommondeps)
inodedeps	= $(filemapdeps) inode.c kernel/inode.c super.c
superdeps	= $(inodedeps) kernel/commit.c super.c kernel/super.c
xattrdeps	= kernel/balloc.c $(xattrcommondeps)

all: $(binaries)
tests: buffertest balloctest committest dleaftest ileaftest btreetest dirtest iattrtest xattrtest filemaptest inodetest

# standalone and library
buffer.o: $(tuxdeps) $(bufferdeps)
diskio.o: $(tuxdeps) $(diskiodeps)
vfs.o: $(tuxdeps) $(vfsdeps)
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
xattr.o:$(basedeps) $(xattrdeps)
# programs
tux3.o:$(basedeps) $(superdeps)
tux3fuse.o:$(basedeps) $(superdeps)
tux3graph.o:$(basedeps) $(superdeps)

buffer: buffer.o diskio.o
dleaf: vfs.o dleaf.o
balloc: vfs.o balloc.o
ileaf: vfs.o ileaf.o
btree: vfs.o btree.o
dir: vfs.o dir.o
iattr: vfs.o iattr.o
xattr: vfs.o xattr.o
inode: vfs.o inode.o
filemap: vfs.o filemap.o
commit: vfs.o commit.o

.c.o:
	$(CC) $(CFLAGS) -Dbuild_$(<:.c=) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) -Dbuild_$(<:.c=) $(CHECKFLAGS) -c $<
endif

$(testbin):
	$(CC) $(CFLAGS) $^ -o $@

buffertest: buffer
	$(VG) ./buffer

balloctest: balloc
	$(VG) ./balloc

dleaftest: dleaf
	$(VG) ./dleaf

ileaftest: ileaf
	$(VG) ./ileaf

btreetest: btree
	$(VG) ./btree foodev

dirtest: dir
	$(VG) ./dir

iattrtest: iattr
	$(VG) ./iattr

xattrtest: xattr
	$(VG) ./xattr foodev

filemaptest: filemap
	$(VG) ./filemap foodev

inodetest: inode
	$(VG) ./inode foodev

committest: commit
	$(VG) ./commit foodev

tux3: vfs.o tux3.o
	$(CC) $(CFLAGS) vfs.o tux3.o -lpopt -otux3

tux3fuse: vfs.o tux3fuse.o
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) vfs.o tux3fuse.c -lfuse -otux3fuse
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

tux3graph: vfs.o tux3graph.o
	$(CC) $(CFLAGS) vfs.o tux3graph.o -lpopt -o $@

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
