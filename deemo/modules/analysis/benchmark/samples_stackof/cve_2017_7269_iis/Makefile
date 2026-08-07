# CVE-2017-7269 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2017_7269_iis_stackof_O0 cve_2017_7269_iis_stackof_O2 cve_2017_7269_iis_stackof_Os

cve_2017_7269_iis_stackof_O0: cve_2017_7269_iis_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2017_7269_iis_stackof_O2: cve_2017_7269_iis_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2017_7269_iis_stackof_Os: cve_2017_7269_iis_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2017_7269_iis_stackof_O0 cve_2017_7269_iis_stackof_O2 cve_2017_7269_iis_stackof_Os
