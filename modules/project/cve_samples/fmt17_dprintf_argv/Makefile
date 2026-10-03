CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt17_dprintf_argv

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
