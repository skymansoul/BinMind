CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall
TARGET = uaf_realloc_path.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
