CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_uaf_basic.exe
SRC = vuln_uaf_basic.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
