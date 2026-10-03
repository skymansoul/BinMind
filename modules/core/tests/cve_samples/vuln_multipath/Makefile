# vuln_multipath — MULTIPATH
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = vuln_multipath.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
