# CVE-2016-6187 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2016_6187_compat_intof_O0 cve_2016_6187_compat_intof_O2 cve_2016_6187_compat_intof_Os

cve_2016_6187_compat_intof_O0: cve_2016_6187_compat_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2016_6187_compat_intof_O2: cve_2016_6187_compat_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2016_6187_compat_intof_Os: cve_2016_6187_compat_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2016_6187_compat_intof_O0 cve_2016_6187_compat_intof_O2 cve_2016_6187_compat_intof_Os
