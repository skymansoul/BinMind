CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int11_shl_wrap_alloc

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
