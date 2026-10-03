# safe_heap — SAFE-HEAP
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = safe_heap.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
