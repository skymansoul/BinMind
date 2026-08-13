CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall
TARGET = uaf_double_free.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
