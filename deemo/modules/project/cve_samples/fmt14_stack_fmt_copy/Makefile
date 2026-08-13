CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt14_stack_fmt_copy

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
