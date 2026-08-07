# Makefile for sample_08 — Nested struct overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_08
SRC = sample_08.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
