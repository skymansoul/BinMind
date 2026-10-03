CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_memcpy_nocheck
SRC = vuln_memcpy_nocheck.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
