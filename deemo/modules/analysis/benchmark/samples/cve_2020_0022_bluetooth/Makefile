# CVE-2020-0022 — 堆溢出基准测试样本
# 编译: make (生成 -O0, -O2, -Os 三个版本)

CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: cve_2020_0022_bluetooth_heap_O0 cve_2020_0022_bluetooth_heap_O2 cve_2020_0022_bluetooth_heap_Os

cve_2020_0022_bluetooth_heap_O0: cve_2020_0022_bluetooth_heap_overflow.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2020_0022_bluetooth_heap_O2: cve_2020_0022_bluetooth_heap_overflow.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2020_0022_bluetooth_heap_Os: cve_2020_0022_bluetooth_heap_overflow.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2020_0022_bluetooth_heap_O0 cve_2020_0022_bluetooth_heap_O2 cve_2020_0022_bluetooth_heap_Os
