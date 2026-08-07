# CVE-2012-0809 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2012_0809_sudo_stackof_O0 cve_2012_0809_sudo_stackof_O2 cve_2012_0809_sudo_stackof_Os

cve_2012_0809_sudo_stackof_O0: cve_2012_0809_sudo_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2012_0809_sudo_stackof_O2: cve_2012_0809_sudo_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2012_0809_sudo_stackof_Os: cve_2012_0809_sudo_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2012_0809_sudo_stackof_O0 cve_2012_0809_sudo_stackof_O2 cve_2012_0809_sudo_stackof_Os
