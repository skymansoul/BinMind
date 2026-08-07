# CVE-2017-7857 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2017_7857_freetype_doublefree_O0 cve_2017_7857_freetype_doublefree_O2 cve_2017_7857_freetype_doublefree_Os

cve_2017_7857_freetype_doublefree_O0: cve_2017_7857_freetype_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2017_7857_freetype_doublefree_O2: cve_2017_7857_freetype_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2017_7857_freetype_doublefree_Os: cve_2017_7857_freetype_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2017_7857_freetype_doublefree_O0 cve_2017_7857_freetype_doublefree_O2 cve_2017_7857_freetype_doublefree_Os
