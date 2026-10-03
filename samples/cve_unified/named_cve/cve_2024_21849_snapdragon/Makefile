CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = snapdragon_overflow

all: $(TARGET)

$(TARGET): snapdragon_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
