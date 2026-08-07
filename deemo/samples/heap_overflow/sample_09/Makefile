# Makefile for sample_09 — Function pointer table overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_09
SRC = sample_09.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
