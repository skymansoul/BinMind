# CVE-2013-1959 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2013_1959_userns_intof_O0 cve_2013_1959_userns_intof_O2 cve_2013_1959_userns_intof_Os

cve_2013_1959_userns_intof_O0: cve_2013_1959_userns_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2013_1959_userns_intof_O2: cve_2013_1959_userns_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2013_1959_userns_intof_Os: cve_2013_1959_userns_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2013_1959_userns_intof_O0 cve_2013_1959_userns_intof_O2 cve_2013_1959_userns_intof_Os
