# Makefile for sample_04 — calloc integer overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_04
SRC = sample_04.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
