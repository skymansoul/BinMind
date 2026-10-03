CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-stack-protector -no-pie
TARGET = sample

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET) 64

.PHONY: all clean run
