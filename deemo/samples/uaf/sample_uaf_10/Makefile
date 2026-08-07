# Makefile for sample_uaf_10
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_uaf_10
SRC = sample_uaf_10.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
