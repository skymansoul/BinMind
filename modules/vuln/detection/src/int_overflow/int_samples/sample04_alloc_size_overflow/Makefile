CC := gcc
CFLAGS := -Wall -Wextra -g -O0
TARGET := main

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
