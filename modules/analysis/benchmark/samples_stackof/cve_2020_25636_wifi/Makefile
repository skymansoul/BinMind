# CVE-2020-25636 — Stack Overflow Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2020_25636_wifi_stackof_O0 cve_2020_25636_wifi_stackof_O2 cve_2020_25636_wifi_stackof_Os

cve_2020_25636_wifi_stackof_O0: cve_2020_25636_wifi_stackof.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_25636_wifi_stackof_O2: cve_2020_25636_wifi_stackof.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_25636_wifi_stackof_Os: cve_2020_25636_wifi_stackof.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_25636_wifi_stackof_O0 cve_2020_25636_wifi_stackof_O2 cve_2020_25636_wifi_stackof_Os
