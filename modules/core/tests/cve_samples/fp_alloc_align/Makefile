# fp_alloc_align — SAFE-ALLOC-ALIGN
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = fp_alloc_align.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
