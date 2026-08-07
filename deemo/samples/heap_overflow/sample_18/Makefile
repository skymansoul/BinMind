# Makefile for sample_18 — memmove overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_18
SRC = sample_18.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
