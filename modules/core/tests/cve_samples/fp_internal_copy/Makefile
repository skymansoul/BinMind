# fp_internal_copy — SAFE-INTERNAL
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = fp_internal_copy.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
