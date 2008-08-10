CC=gcc
CFLAGS += -std=gnu99 -Wall
VG=valgrind
VGFLAGS=--error-exitcode=200
binaries = dleaf ileaf btree dir

all: $(binaries)
tests: dleaftest ileaftest

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

clean:
	rm -f $(binaries) *.o a.out foodev
