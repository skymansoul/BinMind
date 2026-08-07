# CVE-2020-27820 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2020_27820_kernel_fmt_O0 cve_2020_27820_kernel_fmt_O2 cve_2020_27820_kernel_fmt_Os

cve_2020_27820_kernel_fmt_O0: cve_2020_27820_kernel_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_27820_kernel_fmt_O2: cve_2020_27820_kernel_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_27820_kernel_fmt_Os: cve_2020_27820_kernel_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_27820_kernel_fmt_O0 cve_2020_27820_kernel_fmt_O2 cve_2020_27820_kernel_fmt_Os
