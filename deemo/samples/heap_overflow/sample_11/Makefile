# Makefile for sample_11 — Conditional path overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_11
SRC = sample_11.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
