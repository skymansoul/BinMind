CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = off_by_one

all: $(TARGET)

$(TARGET): off_by_one.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
