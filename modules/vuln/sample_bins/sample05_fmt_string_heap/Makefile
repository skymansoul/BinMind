CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_fmt_heap
SRC = vuln_fmt_heap.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
