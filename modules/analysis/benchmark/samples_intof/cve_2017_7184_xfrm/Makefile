# CVE-2017-7184 — Integer Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2017_7184_xfrm_intof_O0 cve_2017_7184_xfrm_intof_O2 cve_2017_7184_xfrm_intof_Os

cve_2017_7184_xfrm_intof_O0: cve_2017_7184_xfrm_intof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2017_7184_xfrm_intof_O2: cve_2017_7184_xfrm_intof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2017_7184_xfrm_intof_Os: cve_2017_7184_xfrm_intof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2017_7184_xfrm_intof_O0 cve_2017_7184_xfrm_intof_O2 cve_2017_7184_xfrm_intof_Os
