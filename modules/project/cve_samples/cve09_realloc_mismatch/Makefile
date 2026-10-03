CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = cve09_realloc_mismatch

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
