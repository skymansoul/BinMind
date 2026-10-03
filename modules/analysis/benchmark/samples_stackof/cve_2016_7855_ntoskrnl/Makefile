# CVE-2016-7855 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2016_7855_ntoskrnl_stackof_O0 cve_2016_7855_ntoskrnl_stackof_O2 cve_2016_7855_ntoskrnl_stackof_Os

cve_2016_7855_ntoskrnl_stackof_O0: cve_2016_7855_ntoskrnl_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2016_7855_ntoskrnl_stackof_O2: cve_2016_7855_ntoskrnl_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2016_7855_ntoskrnl_stackof_Os: cve_2016_7855_ntoskrnl_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2016_7855_ntoskrnl_stackof_O0 cve_2016_7855_ntoskrnl_stackof_O2 cve_2016_7855_ntoskrnl_stackof_Os
