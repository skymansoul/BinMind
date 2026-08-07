# Makefile for sample_uaf_01
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_01
SRC = sample_uaf_01.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
