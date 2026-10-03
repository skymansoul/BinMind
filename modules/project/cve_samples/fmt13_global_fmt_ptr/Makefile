CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt13_global_fmt_ptr

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
