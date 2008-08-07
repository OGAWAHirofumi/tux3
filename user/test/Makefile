CC=gcc
CFLAGS += -std=gnu99
VG=valgrind
VGFLAGS=--error-exitcode=200

all: fleaf ileaf
tests: fleaftest ileaftest

fleaf: fleaf.c tux3.h hexdump.c
	$(CC) $(CFLAGS) fleaf.c -o fleaf
fleaftest: fleaf
	$(VG) $(VGFLAGS) ./fleaf

ileaf: ileaf.c tux3.h hexdump.c
	$(CC) $(CFLAGS) ileaf.c -o ileaf
ileaftest: fleaf
	$(VG) $(VGFLAGS) ./ileaf

clean:
	rm -f ileaf fleaf *.o
