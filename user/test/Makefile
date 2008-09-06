CC=gcc
CFLAGS += -std=gnu99 -Wall -D_FILE_OFFSET_BITS=64
VG=valgrind
VGFLAGS=--error-exitcode=200
binaries = dleaf ileaf iattr btree dir inode tux3 tux3fs testdev

all: $(binaries)
tests: dleaftest ileaftest dirtest iattrtest inodetest

dleaf: dleaf.c tux3.h
	$(CC) $(CFLAGS) dleaf.c -o dleaf
dleaftest: dleaf
	$(VG) $(VGFLAGS) ./dleaf

ileaf: ileaf.c tux3.h
	$(CC) $(CFLAGS) ileaf.c -o ileaf
ileaftest: ileaf
	$(VG) $(VGFLAGS) ./ileaf

btree: btree.c diskio.c buffer.c dleaf.c buffer.h tux3.h
	$(CC) $(CFLAGS) btree.c buffer.c diskio.c -o btree
btreetest: btree
	$(VG) $(VGFLAGS) ./btree foodev

dir: dir.c diskio.c buffer.c dleaf.c buffer.h tux3.h
	$(CC) $(CFLAGS) dir.c buffer.c diskio.c -o dir
dirtest: dir
	$(VG) $(VGFLAGS) ./dir

iattr: iattr.c tux3.h
	$(CC) $(CFLAGS) iattr.c -o iattr
iattrtest: iattr
	$(VG) $(VGFLAGS) ./iattr

inode: inode.c buffer.h tux3.h buffer.c buffer.h diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c
	$(CC) $(CFLAGS) inode.c buffer.c diskio.c -o inode
inodetest: inode
	$(VG) $(VGFLAGS) ./inode foodev

tux3: inode.c buffer.h tux3.h buffer.c buffer.h diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c tux3.c
	$(CC) $(CFLAGS) buffer.c diskio.c tux3.c -lpopt -otux3

tux3fs: inode.c buffer.h tux3.h buffer.c buffer.h diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c tux3fs.c
	$(CC) $(CFLAGS) buffer.c diskio.c tux3fs.c -lfuse -otux3fs

makefs: tux3 tux3fs
	dd if=/dev/zero of=testdev bs=1 count=1 seek=1M
	./tux3 mkfs testdev
	mkdir test || true

testfs: makefs
	sudo ./tux3fs testdev test
	sudo ls -ld test

fstest: tux3fs
	sudo ./tux3fs testdev test -f

untest:
	sudo umount test || true
	rmdir test

unbork:
	sudo umount -l test

clean:
	rm -f $(binaries) *.o a.out foodev
