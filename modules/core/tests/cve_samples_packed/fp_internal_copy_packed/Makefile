CC ?= gcc
CFLAGS ?= -std=c11 -O0 -s -Wall
TARGET = fp_internal_copy_packed.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
