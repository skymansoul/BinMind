# CVE-2022-0995 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2022_0995_watch_uaf_O0 cve_2022_0995_watch_uaf_O2 cve_2022_0995_watch_uaf_Os

cve_2022_0995_watch_uaf_O0: cve_2022_0995_watch_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2022_0995_watch_uaf_O2: cve_2022_0995_watch_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2022_0995_watch_uaf_Os: cve_2022_0995_watch_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2022_0995_watch_uaf_O0 cve_2022_0995_watch_uaf_O2 cve_2022_0995_watch_uaf_Os
