CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = ghost

all: $(TARGET)

$(TARGET): ghost.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
