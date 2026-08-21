# Makefile for cve_2021_34866_ebpf_uaf
# Type: uaf

CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -no-pie -fno-stack-protector
SRC = vuln.c
BIN = vuln

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

.PHONY: all clean
