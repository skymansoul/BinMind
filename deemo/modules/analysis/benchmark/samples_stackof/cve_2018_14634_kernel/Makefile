# CVE-2018-14634 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2018_14634_kernel_stackof_O0 cve_2018_14634_kernel_stackof_O2 cve_2018_14634_kernel_stackof_Os

cve_2018_14634_kernel_stackof_O0: cve_2018_14634_kernel_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_14634_kernel_stackof_O2: cve_2018_14634_kernel_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_14634_kernel_stackof_Os: cve_2018_14634_kernel_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_14634_kernel_stackof_O0 cve_2018_14634_kernel_stackof_O2 cve_2018_14634_kernel_stackof_Os
