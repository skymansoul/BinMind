# CVE-2024-0010 realloc Shrink Then Overflow
# Pattern: p=realloc(p, 32); memset(p, X, 64) — 旧 size 残留
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
