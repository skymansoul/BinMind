CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt15_double_printf

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
