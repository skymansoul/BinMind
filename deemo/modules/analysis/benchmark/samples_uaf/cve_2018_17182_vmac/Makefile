# CVE-2018-17182 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2018_17182_vmac_uaf_O0 cve_2018_17182_vmac_uaf_O2 cve_2018_17182_vmac_uaf_Os

cve_2018_17182_vmac_uaf_O0: cve_2018_17182_vmac_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2018_17182_vmac_uaf_O2: cve_2018_17182_vmac_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2018_17182_vmac_uaf_Os: cve_2018_17182_vmac_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2018_17182_vmac_uaf_O0 cve_2018_17182_vmac_uaf_O2 cve_2018_17182_vmac_uaf_Os
