# CVE-2014-2851 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2014_2851_ping_intof_O0 cve_2014_2851_ping_intof_O2 cve_2014_2851_ping_intof_Os

cve_2014_2851_ping_intof_O0: cve_2014_2851_ping_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2014_2851_ping_intof_O2: cve_2014_2851_ping_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2014_2851_ping_intof_Os: cve_2014_2851_ping_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2014_2851_ping_intof_O0 cve_2014_2851_ping_intof_O2 cve_2014_2851_ping_intof_Os
