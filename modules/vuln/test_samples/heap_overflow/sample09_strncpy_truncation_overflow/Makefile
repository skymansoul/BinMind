# CVE-2024-0009 strncpy Truncation → Overflow
# Pattern: strncpy(buf, src, alloc_size) → 截断无 null term → 后续操作溢出
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
