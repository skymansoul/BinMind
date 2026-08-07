CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = realpath_overflow

all: $(TARGET)

$(TARGET): realpath_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
