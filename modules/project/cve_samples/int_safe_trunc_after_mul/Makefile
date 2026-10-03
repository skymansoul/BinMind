CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = int_safe_trunc_after_mul

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
