# Properly Guarded Write (Safe)
# Pattern: malloc(64); if(idx < 64) buf[idx]=X — 有正确边界检查
# Expected: TN (true negative) — 应判为 safe

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
