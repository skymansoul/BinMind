CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = afpacket_overflow

all: $(TARGET)

$(TARGET): afpacket_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
