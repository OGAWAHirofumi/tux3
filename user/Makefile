CC = gcc -std=gnu99 -Wall -g -rdynamic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CC += -Werror -Wall -Wextra
CC += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers

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
	$(CC) vfs.c -c

balloc: $(basedeps) balloc.c
	$(CC) vfs.o balloc.c -o balloc
balloctest: balloc
	$(VG) ./balloc

dleaf: $(basedeps) dleaf.c
	$(CC) vfs.o dleaf.c -o dleaf
dleaftest: dleaf
	$(VG) ./dleaf

ileaf: $(basedeps) ileaf.c
	$(CC) vfs.o ileaf.c -o ileaf
ileaftest: ileaf
	$(VG) ./ileaf

btree: $(basedeps) btree.c dleaf.c
	$(CC) vfs.o btree.c -o btree
btreetest: btree
	$(VG) ./btree foodev

dir: $(basedeps) dir.c dleaf.c
	$(CC) vfs.o dir.c -o dir
dirtest: dir
	$(VG) ./dir

iattr: $(basedeps) iattr.c
	$(CC) vfs.o iattr.c -o iattr
iattrtest: iattr
	$(VG) ./iattr

xattr: $(lowdeps) xattr.c
	$(CC) vfs.o xattr.c -o xattr
xattrtest: xattr
	$(VG) ./xattr foodev

filemap: $(lowdeps) filemap.c
	$(CC) vfs.o filemap.c -o filemap
filemaptest: filemap
	$(VG) ./filemap foodev

inode: $(fsdeps)
	$(CC) vfs.o inode.c -o inode
inodetest: inode
	$(VG) ./inode foodev

tux3: $(fsdeps) tux3.c
	$(CC) vfs.o tux3.c -lpopt -otux3

tux3fs: $(fsdeps) tux3fs.c
	$(CC) $$(pkg-config --cflags fuse) vfs.o tux3fs.c -lfuse -otux3fs

tux3fuse: $(fsdeps) tux3fuse.c
	$(CC) $$(pkg-config --cflags fuse) vfs.o tux3fuse.c -lfuse -otux3fuse

tux3graph: $(fsdeps) tux3graph.c
	$(CC) vfs.o tux3graph.c -lpopt -o $@

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
