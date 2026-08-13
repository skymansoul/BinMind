CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt12_argv_sprintf

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
