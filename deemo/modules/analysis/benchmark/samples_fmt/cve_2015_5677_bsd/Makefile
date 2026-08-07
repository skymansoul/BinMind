# CVE-2015-5677 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2015_5677_bsd_fmt_O0 cve_2015_5677_bsd_fmt_O2 cve_2015_5677_bsd_fmt_Os

cve_2015_5677_bsd_fmt_O0: cve_2015_5677_bsd_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2015_5677_bsd_fmt_O2: cve_2015_5677_bsd_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2015_5677_bsd_fmt_Os: cve_2015_5677_bsd_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2015_5677_bsd_fmt_O0 cve_2015_5677_bsd_fmt_O2 cve_2015_5677_bsd_fmt_Os
