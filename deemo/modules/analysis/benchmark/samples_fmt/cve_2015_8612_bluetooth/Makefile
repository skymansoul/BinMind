# CVE-2015-8612 — Format String Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2015_8612_bluetooth_fmt_O0 cve_2015_8612_bluetooth_fmt_O2 cve_2015_8612_bluetooth_fmt_Os

cve_2015_8612_bluetooth_fmt_O0: cve_2015_8612_bluetooth_fmt.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2015_8612_bluetooth_fmt_O2: cve_2015_8612_bluetooth_fmt.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2015_8612_bluetooth_fmt_Os: cve_2015_8612_bluetooth_fmt.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2015_8612_bluetooth_fmt_O0 cve_2015_8612_bluetooth_fmt_O2 cve_2015_8612_bluetooth_fmt_Os
