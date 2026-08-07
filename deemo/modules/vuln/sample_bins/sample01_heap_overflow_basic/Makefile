CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_heap_basic
SRC = vuln_heap_basic.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
