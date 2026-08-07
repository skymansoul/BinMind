CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = uaf13_printf_valpass

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
