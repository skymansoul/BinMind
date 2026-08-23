# Makefile for heap_edge_07_sprintf_overflow
# Type: heap_overflow

CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-stack-protector -z execstack
LDFLAGS =

SRC = vuln.c
BIN = vuln

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

.PHONY: all clean
