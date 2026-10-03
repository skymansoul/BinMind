CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = strcpy_overflow

all: $(TARGET)
$(TARGET): strcpy_overflow.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
