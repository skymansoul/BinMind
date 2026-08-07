# CVE-2015-8958 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2015_8958_sunras_intof_O0 cve_2015_8958_sunras_intof_O2 cve_2015_8958_sunras_intof_Os

cve_2015_8958_sunras_intof_O0: cve_2015_8958_sunras_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2015_8958_sunras_intof_O2: cve_2015_8958_sunras_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2015_8958_sunras_intof_Os: cve_2015_8958_sunras_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2015_8958_sunras_intof_O0 cve_2015_8958_sunras_intof_O2 cve_2015_8958_sunras_intof_Os
