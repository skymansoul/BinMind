# Makefile for sample_07 — NON-VULN: malloc(5)+8-byte write (FP test)
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_07
SRC = sample_07.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
