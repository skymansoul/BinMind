# CVE-2018-1000026 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2018_1000026_bcm_intof_O0 cve_2018_1000026_bcm_intof_O2 cve_2018_1000026_bcm_intof_Os

cve_2018_1000026_bcm_intof_O0: cve_2018_1000026_bcm_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_1000026_bcm_intof_O2: cve_2018_1000026_bcm_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_1000026_bcm_intof_Os: cve_2018_1000026_bcm_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_1000026_bcm_intof_O0 cve_2018_1000026_bcm_intof_O2 cve_2018_1000026_bcm_intof_Os
