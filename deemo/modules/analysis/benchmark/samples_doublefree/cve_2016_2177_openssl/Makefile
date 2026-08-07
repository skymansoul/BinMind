# CVE-2016-2177 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2016_2177_openssl_doublefree_O0 cve_2016_2177_openssl_doublefree_O2 cve_2016_2177_openssl_doublefree_Os

cve_2016_2177_openssl_doublefree_O0: cve_2016_2177_openssl_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2016_2177_openssl_doublefree_O2: cve_2016_2177_openssl_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2016_2177_openssl_doublefree_Os: cve_2016_2177_openssl_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2016_2177_openssl_doublefree_O0 cve_2016_2177_openssl_doublefree_O2 cve_2016_2177_openssl_doublefree_Os
