# CVE-2021-32399 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2021_32399_blk_uaf_O0 cve_2021_32399_blk_uaf_O2 cve_2021_32399_blk_uaf_Os

cve_2021_32399_blk_uaf_O0: cve_2021_32399_blk_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2021_32399_blk_uaf_O2: cve_2021_32399_blk_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2021_32399_blk_uaf_Os: cve_2021_32399_blk_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2021_32399_blk_uaf_O0 cve_2021_32399_blk_uaf_O2 cve_2021_32399_blk_uaf_Os
