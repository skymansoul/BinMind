# CVE-2020-10757 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2020_10757_mremap_intof_O0 cve_2020_10757_mremap_intof_O2 cve_2020_10757_mremap_intof_Os

cve_2020_10757_mremap_intof_O0: cve_2020_10757_mremap_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_10757_mremap_intof_O2: cve_2020_10757_mremap_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_10757_mremap_intof_Os: cve_2020_10757_mremap_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_10757_mremap_intof_O0 cve_2020_10757_mremap_intof_O2 cve_2020_10757_mremap_intof_Os
