# CVE-2024-0005 Loop Cumulative Write Overflow
# Pattern: for i in 0..N: memcpy(buf+offset, src, chunk) → 累积 > alloc
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
