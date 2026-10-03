# CVE-2021-3156 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2021_3156_sudo_doublefree_O0 cve_2021_3156_sudo_doublefree_O2 cve_2021_3156_sudo_doublefree_Os

cve_2021_3156_sudo_doublefree_O0: cve_2021_3156_sudo_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2021_3156_sudo_doublefree_O2: cve_2021_3156_sudo_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2021_3156_sudo_doublefree_Os: cve_2021_3156_sudo_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2021_3156_sudo_doublefree_O0 cve_2021_3156_sudo_doublefree_O2 cve_2021_3156_sudo_doublefree_Os
