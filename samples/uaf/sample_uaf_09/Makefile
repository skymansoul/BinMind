# Makefile for sample_uaf_09
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_09
SRC = sample_uaf_09.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
