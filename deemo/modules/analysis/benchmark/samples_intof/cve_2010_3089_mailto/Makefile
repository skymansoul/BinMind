# CVE-2010-3089 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2010_3089_mailto_intof_O0 cve_2010_3089_mailto_intof_O2 cve_2010_3089_mailto_intof_Os

cve_2010_3089_mailto_intof_O0: cve_2010_3089_mailto_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2010_3089_mailto_intof_O2: cve_2010_3089_mailto_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2010_3089_mailto_intof_Os: cve_2010_3089_mailto_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2010_3089_mailto_intof_O0 cve_2010_3089_mailto_intof_O2 cve_2010_3089_mailto_intof_Os
