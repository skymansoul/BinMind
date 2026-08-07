CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = minixml_overflow

all: $(TARGET)

$(TARGET): minixml_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
