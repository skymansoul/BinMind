# Makefile for sample_10 — Signed/unsigned confusion overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_10
SRC = sample_10.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
