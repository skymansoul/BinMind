CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = fmt11_argv_snprintf

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
