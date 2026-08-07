# CVE-2015-0235 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2015_0235_ghost_stackof_O0 cve_2015_0235_ghost_stackof_O2 cve_2015_0235_ghost_stackof_Os

cve_2015_0235_ghost_stackof_O0: cve_2015_0235_ghost_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2015_0235_ghost_stackof_O2: cve_2015_0235_ghost_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2015_0235_ghost_stackof_Os: cve_2015_0235_ghost_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2015_0235_ghost_stackof_O0 cve_2015_0235_ghost_stackof_O2 cve_2015_0235_ghost_stackof_Os
