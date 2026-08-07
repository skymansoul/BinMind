CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_multi_free
SRC = vuln_multi_free.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
