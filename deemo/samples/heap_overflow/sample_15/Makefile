# Makefile for sample_15 — strncpy size mismatch overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_15
SRC = sample_15.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
