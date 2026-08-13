CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt16_loop_argv_fmt

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
