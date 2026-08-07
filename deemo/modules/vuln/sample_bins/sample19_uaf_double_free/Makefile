CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_double_free.exe
SRC = vuln_double_free.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
