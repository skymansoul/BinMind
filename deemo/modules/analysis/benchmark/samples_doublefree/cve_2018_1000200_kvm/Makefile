# CVE-2018-1000200 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2018_1000200_kvm_doublefree_O0 cve_2018_1000200_kvm_doublefree_O2 cve_2018_1000200_kvm_doublefree_Os

cve_2018_1000200_kvm_doublefree_O0: cve_2018_1000200_kvm_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_1000200_kvm_doublefree_O2: cve_2018_1000200_kvm_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_1000200_kvm_doublefree_Os: cve_2018_1000200_kvm_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_1000200_kvm_doublefree_O0 cve_2018_1000200_kvm_doublefree_O2 cve_2018_1000200_kvm_doublefree_Os
