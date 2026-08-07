# FP_uaf_refcount_protected — 引用计数保护 (False Positive)

CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).exe
