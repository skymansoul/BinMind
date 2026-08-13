CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = uaf18_call_arg_after_free

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
