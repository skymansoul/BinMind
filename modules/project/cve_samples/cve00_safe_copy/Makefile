CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = cve00_safe_copy

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
