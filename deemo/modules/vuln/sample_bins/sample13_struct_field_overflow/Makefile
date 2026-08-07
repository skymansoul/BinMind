CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_struct_overflow
SRC = vuln_struct_overflow.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
