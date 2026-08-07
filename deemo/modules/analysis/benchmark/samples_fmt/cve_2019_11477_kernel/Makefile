# CVE-2019-11477 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2019_11477_kernel_fmt_O0 cve_2019_11477_kernel_fmt_O2 cve_2019_11477_kernel_fmt_Os

cve_2019_11477_kernel_fmt_O0: cve_2019_11477_kernel_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2019_11477_kernel_fmt_O2: cve_2019_11477_kernel_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2019_11477_kernel_fmt_Os: cve_2019_11477_kernel_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2019_11477_kernel_fmt_O0 cve_2019_11477_kernel_fmt_O2 cve_2019_11477_kernel_fmt_Os
