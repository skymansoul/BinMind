# Makefile for cwe_122_heap_bof_03_strcpy
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
