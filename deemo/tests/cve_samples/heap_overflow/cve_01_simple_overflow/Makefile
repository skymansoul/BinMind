CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = heap_overflow_basic

all: $(TARGET)

$(TARGET): heap_overflow_basic.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
