CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int10_sub_underflow_len

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
