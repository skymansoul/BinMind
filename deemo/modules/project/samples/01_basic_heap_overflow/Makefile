CC=gcc
CFLAGS=-g -O0 -fno-stack-protector
TARGET=demo

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
