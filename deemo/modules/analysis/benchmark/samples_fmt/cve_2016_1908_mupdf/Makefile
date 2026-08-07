# CVE-2016-1908 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2016_1908_mupdf_fmt_O0 cve_2016_1908_mupdf_fmt_O2 cve_2016_1908_mupdf_fmt_Os

cve_2016_1908_mupdf_fmt_O0: cve_2016_1908_mupdf_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2016_1908_mupdf_fmt_O2: cve_2016_1908_mupdf_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2016_1908_mupdf_fmt_Os: cve_2016_1908_mupdf_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2016_1908_mupdf_fmt_O0 cve_2016_1908_mupdf_fmt_O2 cve_2016_1908_mupdf_fmt_Os
