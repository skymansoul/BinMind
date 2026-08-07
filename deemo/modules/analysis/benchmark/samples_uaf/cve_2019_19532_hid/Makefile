# CVE-2019-19532 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2019_19532_hid_uaf_O0 cve_2019_19532_hid_uaf_O2 cve_2019_19532_hid_uaf_Os

cve_2019_19532_hid_uaf_O0: cve_2019_19532_hid_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2019_19532_hid_uaf_O2: cve_2019_19532_hid_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2019_19532_hid_uaf_Os: cve_2019_19532_hid_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2019_19532_hid_uaf_O0 cve_2019_19532_hid_uaf_O2 cve_2019_19532_hid_uaf_Os
