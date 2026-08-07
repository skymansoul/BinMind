# CVE-2017-1000370 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2017_1000370_shiftfs_fmt_O0 cve_2017_1000370_shiftfs_fmt_O2 cve_2017_1000370_shiftfs_fmt_Os

cve_2017_1000370_shiftfs_fmt_O0: cve_2017_1000370_shiftfs_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2017_1000370_shiftfs_fmt_O2: cve_2017_1000370_shiftfs_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2017_1000370_shiftfs_fmt_Os: cve_2017_1000370_shiftfs_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2017_1000370_shiftfs_fmt_O0 cve_2017_1000370_shiftfs_fmt_O2 cve_2017_1000370_shiftfs_fmt_Os
