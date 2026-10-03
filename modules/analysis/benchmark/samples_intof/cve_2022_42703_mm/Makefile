# CVE-2022-42703 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2022_42703_mm_intof_O0 cve_2022_42703_mm_intof_O2 cve_2022_42703_mm_intof_Os

cve_2022_42703_mm_intof_O0: cve_2022_42703_mm_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2022_42703_mm_intof_O2: cve_2022_42703_mm_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2022_42703_mm_intof_Os: cve_2022_42703_mm_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2022_42703_mm_intof_O0 cve_2022_42703_mm_intof_O2 cve_2022_42703_mm_intof_Os
