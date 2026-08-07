# Large Offset Small Write Near Boundary
# Pattern: malloc(2112); write at offset 2048, 8 bytes → 2048+8=2056 ≤ 2112, safe
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
