# Makefile for sample_uaf_14
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_14
SRC = sample_uaf_14.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
