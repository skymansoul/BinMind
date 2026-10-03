# CVE-2017-2636 — UAF基准测试样本
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2017_2636_n_hdlc_uaf_O0 cve_2017_2636_n_hdlc_uaf_O2 cve_2017_2636_n_hdlc_uaf_Os

cve_2017_2636_n_hdlc_uaf_O0: cve_2017_2636_n_hdlc_uaf.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2017_2636_n_hdlc_uaf_O2: cve_2017_2636_n_hdlc_uaf.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2017_2636_n_hdlc_uaf_Os: cve_2017_2636_n_hdlc_uaf.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2017_2636_n_hdlc_uaf_O0 cve_2017_2636_n_hdlc_uaf_O2 cve_2017_2636_n_hdlc_uaf_Os
