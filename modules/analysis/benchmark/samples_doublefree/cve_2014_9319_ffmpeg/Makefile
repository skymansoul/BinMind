# CVE-2014-9319 — Double-Free Benchmark
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: cve_2014_9319_ffmpeg_doublefree_O0 cve_2014_9319_ffmpeg_doublefree_O2 cve_2014_9319_ffmpeg_doublefree_Os

cve_2014_9319_ffmpeg_doublefree_O0: cve_2014_9319_ffmpeg_doublefree.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

cve_2014_9319_ffmpeg_doublefree_O2: cve_2014_9319_ffmpeg_doublefree.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

cve_2014_9319_ffmpeg_doublefree_Os: cve_2014_9319_ffmpeg_doublefree.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f cve_2014_9319_ffmpeg_doublefree_O0 cve_2014_9319_ffmpeg_doublefree_O2 cve_2014_9319_ffmpeg_doublefree_Os
