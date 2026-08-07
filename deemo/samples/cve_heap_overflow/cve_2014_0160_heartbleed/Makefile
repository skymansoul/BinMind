CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = heartbleed

all: $(TARGET)

$(TARGET): heartbleed.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
