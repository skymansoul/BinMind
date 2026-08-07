CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = cve16_loop_byte_write

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
