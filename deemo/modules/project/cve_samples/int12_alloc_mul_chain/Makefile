CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int12_alloc_mul_chain

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
