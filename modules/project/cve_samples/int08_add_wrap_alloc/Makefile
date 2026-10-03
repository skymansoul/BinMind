CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int08_add_wrap_alloc

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
