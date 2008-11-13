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

CHECK = sparse
CHECKFLAGS = -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise -Wno-transparent-union
CHECKFLAGS += -Wno-decl -Wno-declaration-after-statement

VG=valgrind --error-exitcode=200 --leak-check=full

binaries = vfs.o balloc dleaf ileaf iattr xattr btree dir filemap inode tux3 \
	tux3graph

ifeq ($(shell pkg-config fuse && echo found), found)
	binaries += tux3fs tux3fuse
endif

basedeps = Makefile vfs.o trace.h tux3.h
lowdeps = $(basedeps) iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c xattr.c
fsdeps = $(lowdeps) filemap.c inode.c

all: $(binaries)
tests: dleaftest ileaftest dirtest iattrtest inodetest xattrtest

vfs.o: Makefile buffer.h trace.h buffer.c diskio.c vfs.c

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
ifeq ($(C),1)
	$(CHECK) $(CFLAGS) $(CHECKFLAGS) -c $<
endif

balloc: $(basedeps) balloc.o
	$(CC) $(CFLAGS) vfs.o balloc.o -o balloc
balloctest: balloc
	$(VG) ./balloc

dleaf: $(basedeps) dleaf.o
	$(CC) $(CFLAGS) vfs.o dleaf.o -o dleaf
dleaftest: dleaf
	$(VG) ./dleaf

ileaf: $(basedeps) ileaf.o
	$(CC) $(CFLAGS) vfs.o ileaf.o -o ileaf
ileaftest: ileaf
	$(VG) ./ileaf

btree: $(basedeps) btree.o dleaf.c
	$(CC) $(CFLAGS) vfs.o btree.o -o btree
btreetest: btree
	$(VG) ./btree foodev

dir: $(basedeps) dir.o dleaf.c
	$(CC) $(CFLAGS) vfs.o dir.o -o dir
dirtest: dir
	$(VG) ./dir

iattr: $(basedeps) iattr.o
	$(CC) $(CFLAGS) vfs.o iattr.o -o iattr
iattrtest: iattr
	$(VG) ./iattr

xattr: $(lowdeps) xattr.o
	$(CC) $(CFLAGS) vfs.o xattr.o -o xattr
xattrtest: xattr
	$(VG) ./xattr foodev

filemap: $(lowdeps) filemap.o
	$(CC) $(CFLAGS) vfs.o filemap.o -o filemap
filemaptest: filemap
	$(VG) ./filemap foodev

inode: $(fsdeps) inode.o
	$(CC) $(CFLAGS) vfs.o inode.o -o inode
inodetest: inode
	$(VG) ./inode foodev

tux3: $(fsdeps) tux3.o
	$(CC) $(CFLAGS) vfs.o tux3.o -lpopt -otux3

tux3fs: $(fsdeps) tux3fs.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) vfs.o tux3fs.c -lfuse -otux3fs
ifeq ($(C),1)
	$(CHECK) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fs.c
endif

tux3fuse: $(fsdeps) tux3fuse.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) vfs.o tux3fuse.c -lfuse -otux3fuse
ifeq ($(C),1)
	$(CHECK) $(CFLAGS) $(CHECKFLAGS) $$(pkg-config --cflags fuse) tux3fuse.c
endif

tux3graph: $(fsdeps) tux3graph.o
	$(CC) $(CFLAGS) vfs.o tux3graph.o -lpopt -o $@

makefs mkfs: tux3 tux3fs
	dd if=/dev/zero of=/tmp/testdev bs=1 count=1 seek=1M
	./tux3 mkfs /tmp/testdev
	mkdir -p /tmp/test

testfs: makefs
	sudo ./tux3fs /tmp/testdev /tmp/test
	sudo ls -ld /tmp/test

debug: tux3fs
	mkdir -p /tmp/test
	sudo ./tux3fs /tmp/testdev /tmp/test -f

testfuse: makefs
	sudo ./tux3fuse /tmp/testdev /tmp/test
	sudo ls -ld /tmp/test

defuse: tux3fuse
	mkdir -p /tmp/test
	sudo ./tux3fuse /tmp/testdev /tmp/test -f

untest:
	sudo umount /tmp/test || true
	rmdir /tmp/test

unbork:
	sudo umount -l /tmp/test

clean:
	rm -f $(binaries) *.o a.out foodev
