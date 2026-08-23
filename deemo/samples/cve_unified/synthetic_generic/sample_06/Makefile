# Makefile for sample_06 — Loop with stride-based index overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_06
SRC = sample_06.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
