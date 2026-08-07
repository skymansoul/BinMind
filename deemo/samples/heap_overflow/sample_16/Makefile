# Makefile for sample_16 — realloc NULL handling edge case
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_16
SRC = sample_16.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
