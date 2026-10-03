# CVE-2018-7566 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2018_7566_alsa_doublefree_O0 cve_2018_7566_alsa_doublefree_O2 cve_2018_7566_alsa_doublefree_Os

cve_2018_7566_alsa_doublefree_O0: cve_2018_7566_alsa_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_7566_alsa_doublefree_O2: cve_2018_7566_alsa_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_7566_alsa_doublefree_Os: cve_2018_7566_alsa_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_7566_alsa_doublefree_O0 cve_2018_7566_alsa_doublefree_O2 cve_2018_7566_alsa_doublefree_Os
