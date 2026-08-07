# Makefile for sample_02 — Off-by-one loop overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_02
SRC = sample_02.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
