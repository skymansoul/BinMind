CC ?= gcc
CFLAGS ?= -std=c11 -O0 -s -Wall
TARGET = safe_01_packed.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
