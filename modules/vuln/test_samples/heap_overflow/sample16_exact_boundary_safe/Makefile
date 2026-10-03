# Exact Boundary Write (Safe)
# Pattern: malloc(64); memset(buf+60, 0, 4) — 60+4=64, 恰好在边界
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
