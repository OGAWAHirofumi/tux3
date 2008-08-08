CC=gcc
CFLAGS += -std=gnu99 -Wall
VG=valgrind
VGFLAGS=--error-exitcode=200

all: dleaf ileaf btree
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

clean:
	rm -f dleaf ileaf btree *.o a.out foodev
