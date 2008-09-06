CC=gcc
CFLAGS += -std=gnu99 -Wall -D_FILE_OFFSET_BITS=64
VG=valgrind
VGFLAGS=--error-exitcode=200
binaries = dleaf ileaf iattr btree dir inode tux3fs

all: $(binaries)
tests: dleaftest ileaftest dirtest iattrtest inodetest

dleaf: dleaf.c tux3.h hexdump.c
	$(CC) $(CFLAGS) dleaf.c -o dleaf
dleaftest: dleaf
	$(VG) $(VGFLAGS) ./dleaf

ileaf: ileaf.c tux3.h hexdump.c
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

iattr: iattr.c tux3.h hexdump.c
	$(CC) $(CFLAGS) iattr.c -o iattr
iattrtest: iattr
	$(VG) $(VGFLAGS) ./iattr

inode: inode.c buffer.h tux3.h buffer.c buffer.h diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c hexdump.c
	$(CC) $(CFLAGS) inode.c buffer.c diskio.c -o inode
inodetest: inode
	$(VG) $(VGFLAGS) ./inode foodev

tux3fs: inode.c buffer.h tux3.h buffer.c buffer.h diskio.c iattr.c dir.c btree.c ileaf.c balloc.c dleaf.c hexdump.c tux3fs.c
	$(CC) $(CFLAGS) buffer.c diskio.c tux3fs.c -lfuse -otux3fs

clean:
	rm -f $(binaries) *.o a.out foodev
