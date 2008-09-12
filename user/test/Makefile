CC=gcc
CFLAGS += -std=gnu99 -Wall -g
VG=valgrind
VGFLAGS=--error-exitcode=200

binaries = buffer.o dleaf ileaf iattr btree dir inode tux3

ifeq ($(shell pkg-config fuse && echo found), found)
	binaries += tux3fs tux3fuse
endif

basedeps = Makefile buffer.o trace.h tux3.h
fsdeps = $(basedeps) iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c xattr.c inode.c

all: $(binaries)
tests: dleaftest ileaftest dirtest iattrtest inodetest

buffer.o: Makefile buffer.h trace.h buffer.c
	$(CC) $(CFLAGS) -Dmain=notmain buffer.c -c

dleaf: $(basedeps) dleaf.c
	$(CC) $(CFLAGS) buffer.o dleaf.c -o dleaf
dleaftest: dleaf
	$(VG) $(VGFLAGS) ./dleaf

ileaf: $(basedeps) ileaf.c
	$(CC) $(CFLAGS) buffer.o ileaf.c -o ileaf
ileaftest: ileaf
	$(VG) $(VGFLAGS) ./ileaf

btree: $(basedeps) btree.c dleaf.c
	$(CC) $(CFLAGS) buffer.o btree.c -o btree
btreetest: btree
	$(VG) $(VGFLAGS) ./btree foodev

dir: $(basedeps) dir.c dleaf.c
	$(CC) $(CFLAGS) buffer.o dir.c -o dir
dirtest: dir
	$(VG) $(VGFLAGS) ./dir

iattr: $(basedeps) iattr.c
	$(CC) $(CFLAGS) buffer.o iattr.c -o iattr
iattrtest: iattr
	$(VG) $(VGFLAGS) ./iattr

inode: $(fsdeps)
	$(CC) $(CFLAGS) buffer.o inode.c -o inode
inodetest: inode
	$(VG) $(VGFLAGS) ./inode foodev

tux3: $(fsdeps) tux3.c
	$(CC) $(CFLAGS) buffer.o tux3.c -lpopt -otux3

tux3fs: $(fsdeps) tux3fs.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) buffer.o tux3fs.c -lfuse -otux3fs

tux3fuse: $(fsdeps) tux3fuse.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) buffer.o tux3fuse.c -lfuse -otux3fuse

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
