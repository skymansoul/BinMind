# Makefile for sample_03 — strlen without +1 null terminator
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_03
SRC = sample_03.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
