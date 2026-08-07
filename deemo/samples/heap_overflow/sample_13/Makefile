# Makefile for sample_13 — Struct padding stride overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_13
SRC = sample_13.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
