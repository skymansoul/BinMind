CC = gcc
CFLAGS = -O0 -g -Wall -w
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

O3: vuln.c
	$(CC) -O3 -g -Wall -w -o vuln_O3 vuln.c

clean:
	rm -f $(TARGET) vuln_O3

.PHONY: all clean O3
