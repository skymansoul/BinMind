# CVE-2018-12020 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2018_12020_gnupg_fmt_O0 cve_2018_12020_gnupg_fmt_O2 cve_2018_12020_gnupg_fmt_Os

cve_2018_12020_gnupg_fmt_O0: cve_2018_12020_gnupg_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_12020_gnupg_fmt_O2: cve_2018_12020_gnupg_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_12020_gnupg_fmt_Os: cve_2018_12020_gnupg_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_12020_gnupg_fmt_O0 cve_2018_12020_gnupg_fmt_O2 cve_2018_12020_gnupg_fmt_Os
