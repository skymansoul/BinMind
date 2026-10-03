# Makefile for sample_fmt_01
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_fmt_01
SRC = sample_fmt_01.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
