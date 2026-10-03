CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall
TARGET = fmt_safe_string.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
