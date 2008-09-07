CC=gcc
CFLAGS += -std=gnu99 -Wall
VG=valgrind
VGFLAGS=--error-exitcode=200
binaries = dleaf ileaf iattr btree dir inode tux3 tux3fs
basedeps = Makefile tux3.h buffer.h trace.h
fsdeps = $(basedeps) buffer.c diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c inode.c

all: $(binaries)
tests: dleaftest ileaftest dirtest iattrtest inodetest

dleaf: $(basedeps) dleaf.c
	$(CC) $(CFLAGS) dleaf.c -o dleaf
dleaftest: dleaf
	$(VG) $(VGFLAGS) ./dleaf

ileaf: $(basedeps) ileaf.c
	$(CC) $(CFLAGS) ileaf.c -o ileaf
ileaftest: ileaf
	$(VG) $(VGFLAGS) ./ileaf

btree: $(basedeps) btree.c diskio.c buffer.c dleaf.c
	$(CC) $(CFLAGS) btree.c buffer.c diskio.c -o btree
btreetest: btree
	$(VG) $(VGFLAGS) ./btree foodev

dir: $(basedeps) dir.c diskio.c buffer.c dleaf.c
	$(CC) $(CFLAGS) dir.c buffer.c diskio.c -o dir
dirtest: dir
	$(VG) $(VGFLAGS) ./dir

iattr: $(basedeps) iattr.c
	$(CC) $(CFLAGS) iattr.c -o iattr
iattrtest: iattr
	$(VG) $(VGFLAGS) ./iattr

inode: $(fsdeps)
	$(CC) $(CFLAGS) inode.c buffer.c diskio.c -o inode
inodetest: inode
	$(VG) $(VGFLAGS) ./inode foodev

tux3: $(fsdeps) tux3.c
	$(CC) $(CFLAGS) buffer.c diskio.c tux3.c -lpopt -otux3

tux3fs: $(fsdeps) tux3fs.c
	$(CC) $(CFLAGS) $$(pkg-config --cflags fuse) buffer.c diskio.c tux3fs.c -lfuse -otux3fs

makefs mkfs: tux3 tux3fs
	dd if=/dev/zero of=/tmp/testdev bs=1 count=1 seek=1M
	./tux3 mkfs /tmp/testdev
	mkdir /tmp/test || true

testfs: makefs
	sudo ./tux3fs /tmp/testdev /tmp/test
	sudo ls -ld /tmp/test

debug: tux3fs
	mkdir /tmp/test || true
	sudo ./tux3fs /tmp/testdev /tmp/test -f

untest:
	sudo umount /tmp/test || true
	rmdir /tmp/test

unbork:
	sudo umount -l /tmp/test

clean:
	rm -f $(binaries) *.o a.out foodev
