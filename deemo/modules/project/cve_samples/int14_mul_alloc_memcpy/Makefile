CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int14_mul_alloc_memcpy

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
