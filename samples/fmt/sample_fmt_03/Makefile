# Makefile for sample_fmt_03
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample_fmt_03
SRC = sample_fmt_03.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
