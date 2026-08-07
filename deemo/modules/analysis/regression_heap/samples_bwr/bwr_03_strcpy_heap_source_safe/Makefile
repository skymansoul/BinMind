CC = gcc
CFLAGS = -O0 -g -fno-builtin -fno-inline
TARGET = vuln.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) vuln.c -o $(TARGET)

clean:
	rm -f $(TARGET)
