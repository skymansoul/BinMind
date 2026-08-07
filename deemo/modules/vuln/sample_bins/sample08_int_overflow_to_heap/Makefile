CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_int_overflow_heap
SRC = vuln_int_overflow_heap.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
