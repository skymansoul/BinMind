# Makefile for sample_uaf_12
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_12
SRC = sample_uaf_12.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
