# CVE-2019-9213 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2019_9213_nullptr_stackof_O0 cve_2019_9213_nullptr_stackof_O2 cve_2019_9213_nullptr_stackof_Os

cve_2019_9213_nullptr_stackof_O0: cve_2019_9213_nullptr_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2019_9213_nullptr_stackof_O2: cve_2019_9213_nullptr_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2019_9213_nullptr_stackof_Os: cve_2019_9213_nullptr_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2019_9213_nullptr_stackof_O0 cve_2019_9213_nullptr_stackof_O2 cve_2019_9213_nullptr_stackof_Os
