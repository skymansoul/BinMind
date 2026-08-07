# Makefile for sample_17 — sprintf overflow
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_17
SRC = sample_17.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
