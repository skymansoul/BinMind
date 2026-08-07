# CVE-2020-25211 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2020_25211_netfilter_uaf_O0 cve_2020_25211_netfilter_uaf_O2 cve_2020_25211_netfilter_uaf_Os

cve_2020_25211_netfilter_uaf_O0: cve_2020_25211_netfilter_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_25211_netfilter_uaf_O2: cve_2020_25211_netfilter_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_25211_netfilter_uaf_Os: cve_2020_25211_netfilter_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_25211_netfilter_uaf_O0 cve_2020_25211_netfilter_uaf_O2 cve_2020_25211_netfilter_uaf_Os
