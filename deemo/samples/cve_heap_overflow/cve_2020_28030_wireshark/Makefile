CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = wireshark_overflow

all: $(TARGET)

$(TARGET): wireshark_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
