CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_nested_loop
SRC = vuln_nested_loop.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
