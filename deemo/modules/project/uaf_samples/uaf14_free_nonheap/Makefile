CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = uaf14_free_nonheap

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
