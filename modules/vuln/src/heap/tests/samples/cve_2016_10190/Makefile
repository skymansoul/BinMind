# CVE-2016-10190 — FFmpeg HTTP chunk size truncation heap overflow
# Compile: x86_64-w64-mingw32-gcc -O0 -o cve_2016_10190.exe poc.c

CC = x86_64-w64-mingw32-gcc
CFLAGS = -O0 -g -Wall
TARGET = cve_2016_10190.exe

all: $(TARGET)

$(TARGET): poc.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
