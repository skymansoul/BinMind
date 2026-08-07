# CVE-2019-11479 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2019_11479_mss_intof_O0 cve_2019_11479_mss_intof_O2 cve_2019_11479_mss_intof_Os

cve_2019_11479_mss_intof_O0: cve_2019_11479_mss_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2019_11479_mss_intof_O2: cve_2019_11479_mss_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2019_11479_mss_intof_Os: cve_2019_11479_mss_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2019_11479_mss_intof_O0 cve_2019_11479_mss_intof_O2 cve_2019_11479_mss_intof_Os
