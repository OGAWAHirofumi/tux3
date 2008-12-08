ARCH = $(shell uname -m)
CC = gcc
ifeq ($(ARCH),x86_64)
CFLAGS  += -m64
else
CFLAGS  += -m32
endif

CFLAGS += -std=gnu99 -Wall -g -rdynamic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS += -Werror -Wall -Wextra
CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers

CHECKER = sparse
CHECKFLAGS = -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise -Wno-transparent-union
CHECKFLAGS += -Wno-decl -Wno-declaration-after-statement

VG=valgrind --error-exitcode=200 --leak-check=full

TESTDIR = .

binaries = balloc dleaf ileaf iattr xattr btree dir filemap inode tux3 tux3graph

ifeq ($(shell pkg-config fuse && echo found), found)
	binaries += tux3fuse
endif

basedeps	= Makefile err.h buffer.h diskio.h list.h trace.h \
	kernel/trace.h tux3.h kernel/tux3.h hexdump.c kernel/hexdump.c
ballocdeps	= balloc.c kernel/balloc.c
btreedeps	= btree.c kernel/btree.c
dirdeps		= dir.c kernel/dir.c kernel/namei.c
dleafdeps	= dleaf.c kernel/dleaf.c
filemapdeps	= $(btreedeps) $(ballocdeps) $(dleafdeps) $(dirdeps) \
	$(xattrdeps) $(ileafdeps) filemap.c kernel/filemap.c
iattrdeps	= iattr.c kernel/iattr.c
ileafdeps	= $(iattrdeps) ileaf.c kernel/ileaf.c
inodedeps	= $(filemapdeps) inode.c kernel/inode.c super.c kernel/super.c
vfsdeps		= vfs.c buffer.c diskio.c
xattrdeps	= $(ballocdeps) $(dirdeps) $(ileafdeps) xattr.c kernel/xattr.c

all: $(binaries)
tests: balloctest dleaftest ileaftest btreetest dirtest iattrtest xattrtest filemaptest inodetest

balloc.o: $(basedeps) $(ballocdeps)
btree.o: $(basedeps) $(btreedeps)
dir.o: $(basedeps) $(dirdeps)
dleaf.o: $(basedeps) $(dleafdeps)
filemap.o: $(basedeps) $(filemapdeps)
iattr.o: $(basedeps) $(iattrdeps)
ileaf.o: $(basedeps) $(ileafdeps)
inode.o: $(basedeps) $(inodedeps)
tux3.o:$(basedeps) $(inodedeps)
tux3graph.o:$(basedeps) $(inodedeps)
vfs.o: $(basedeps) $(vfsdeps)
xattr.o:$(basedeps) $(xattrdeps)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
ifeq ($(CHECK),1)
	$(CHECKER) $(CFLAGS) $(CHECKFLAGS) -c $<
endif

balloc: vfs.o balloc.o
	$(CC) $(CFLAGS) vfs.o balloc.o -o balloc
balloctest: balloc
	$(VG) ./balloc

dleaf: vfs.o dleaf.o
	$(CC) $(CFLAGS) vfs.o dleaf.o -o dleaf
dleaftest: dleaf
	$(VG) ./dleaf

ileaf: vfs.o ileaf.o
	$(CC) $(CFLAGS) vfs.o ileaf.o -o ileaf
ileaftest: ileaf
	$(VG) ./ileaf

btree: vfs.o btree.o
	$(CC) $(CFLAGS) vfs.o btree.o -o btree
btreetest: btree
	$(VG) ./btree foodev

dir: vfs.o dir.o
	$(CC) $(CFLAGS) vfs.o dir.o -o dir
dirtest: dir
	$(VG) ./dir

iattr: vfs.o iattr.o
	$(CC) $(CFLAGS) vfs.o iattr.o -o iattr
iattrtest: iattr
	$(VG) ./iattr

xattr: vfs.o xattr.o
	$(CC) $(CFLAGS) vfs.o xattr.o -o xattr
xattrtest: xattr
	$(VG) ./xattr foodev

filemap: vfs.o filemap.o
	$(CC) $(CFLAGS) vfs.o filemap.o -o filemap
filemaptest: filemap
	$(VG) ./filemap foodev

inode: vfs.o inode.o
	$(CC) $(CFLAGS) vfs.o inode.o -o inode
inodetest: inode
	$(VG) ./inode foodev

tux3: vfs.o tux3.o
	$(CC) $(CFLAGS) vfs.o tux3.o -lpopt -otux3

tux3fuse: $(basedeps) $(inodedeps) vfs.o
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
