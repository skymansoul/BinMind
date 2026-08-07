# Makefile for sample_12 — Adjacent heap chunk overflow (heap feng shui)
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_12
SRC = sample_12.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
