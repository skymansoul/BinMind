# CVE-2014-3610 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2014_3610_kvm_stackof_O0 cve_2014_3610_kvm_stackof_O2 cve_2014_3610_kvm_stackof_Os

cve_2014_3610_kvm_stackof_O0: cve_2014_3610_kvm_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2014_3610_kvm_stackof_O2: cve_2014_3610_kvm_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2014_3610_kvm_stackof_Os: cve_2014_3610_kvm_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2014_3610_kvm_stackof_O0 cve_2014_3610_kvm_stackof_O2 cve_2014_3610_kvm_stackof_Os
