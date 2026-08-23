# Makefile for sample_14 — malloc(0) edge case
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_14
SRC = sample_14.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
