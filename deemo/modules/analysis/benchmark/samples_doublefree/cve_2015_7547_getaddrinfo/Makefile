# CVE-2015-7547 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2015_7547_getaddrinfo_doublefree_O0 cve_2015_7547_getaddrinfo_doublefree_O2 cve_2015_7547_getaddrinfo_doublefree_Os

cve_2015_7547_getaddrinfo_doublefree_O0: cve_2015_7547_getaddrinfo_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2015_7547_getaddrinfo_doublefree_O2: cve_2015_7547_getaddrinfo_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2015_7547_getaddrinfo_doublefree_Os: cve_2015_7547_getaddrinfo_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2015_7547_getaddrinfo_doublefree_O0 cve_2015_7547_getaddrinfo_doublefree_O2 cve_2015_7547_getaddrinfo_doublefree_Os
