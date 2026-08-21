CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -no-pie -fno-stack-protector
TARGET = vuln
SRC = vuln.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
