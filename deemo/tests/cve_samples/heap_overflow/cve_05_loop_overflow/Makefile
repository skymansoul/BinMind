CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = loop_overflow

all: $(TARGET)
$(TARGET): loop_overflow.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
