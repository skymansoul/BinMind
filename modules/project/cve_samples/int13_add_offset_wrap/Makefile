CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int13_add_offset_wrap

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
