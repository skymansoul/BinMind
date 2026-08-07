# CVE-2020-14356 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2020_14356_kernel_doublefree_O0 cve_2020_14356_kernel_doublefree_O2 cve_2020_14356_kernel_doublefree_Os

cve_2020_14356_kernel_doublefree_O0: cve_2020_14356_kernel_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_14356_kernel_doublefree_O2: cve_2020_14356_kernel_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_14356_kernel_doublefree_Os: cve_2020_14356_kernel_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_14356_kernel_doublefree_O0 cve_2020_14356_kernel_doublefree_O2 cve_2020_14356_kernel_doublefree_Os
