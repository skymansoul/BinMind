# CVE-2024-0013 Multi-Allocation Pointer Confusion
# Pattern: p1=malloc(32); p2=malloc(64); memset(p1, X, 64) — 写到 p2 空间
# Expected: TP (true positive)

CC = gcc
CFLAGS = -Wall -O0 -g -fno-builtin
TARGET = main

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

disasm: $(TARGET)
	objdump -d -M intel $(TARGET) > $(TARGET).asm

clean:
	rm -f $(TARGET) $(TARGET).asm

.PHONY: all disasm clean
