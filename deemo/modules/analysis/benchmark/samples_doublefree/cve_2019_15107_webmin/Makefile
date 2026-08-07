# CVE-2019-15107 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2019_15107_webmin_doublefree_O0 cve_2019_15107_webmin_doublefree_O2 cve_2019_15107_webmin_doublefree_Os

cve_2019_15107_webmin_doublefree_O0: cve_2019_15107_webmin_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2019_15107_webmin_doublefree_O2: cve_2019_15107_webmin_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2019_15107_webmin_doublefree_Os: cve_2019_15107_webmin_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2019_15107_webmin_doublefree_O0 cve_2019_15107_webmin_doublefree_O2 cve_2019_15107_webmin_doublefree_Os
