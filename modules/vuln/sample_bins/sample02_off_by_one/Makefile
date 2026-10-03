CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_off_by_one
SRC = vuln_off_by_one.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
