# Makefile for sample_05 — realloc shrink then old-size write
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_05
SRC = sample_05.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
