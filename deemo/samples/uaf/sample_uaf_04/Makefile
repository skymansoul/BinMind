# Makefile for sample_uaf_04
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_04
SRC = sample_uaf_04.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
