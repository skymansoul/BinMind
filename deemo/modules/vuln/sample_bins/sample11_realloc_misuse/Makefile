CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_realloc
SRC = vuln_realloc.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
