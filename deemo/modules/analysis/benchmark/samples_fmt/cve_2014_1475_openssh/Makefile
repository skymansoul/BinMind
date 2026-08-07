# CVE-2014-1475 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2014_1475_openssh_fmt_O0 cve_2014_1475_openssh_fmt_O2 cve_2014_1475_openssh_fmt_Os

cve_2014_1475_openssh_fmt_O0: cve_2014_1475_openssh_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2014_1475_openssh_fmt_O2: cve_2014_1475_openssh_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2014_1475_openssh_fmt_Os: cve_2014_1475_openssh_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2014_1475_openssh_fmt_O0 cve_2014_1475_openssh_fmt_O2 cve_2014_1475_openssh_fmt_Os
