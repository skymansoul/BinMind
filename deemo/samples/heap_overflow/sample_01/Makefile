# Makefile for sample_01 — Basic heap overflow: malloc + memcpy
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_01
SRC = sample_01.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
