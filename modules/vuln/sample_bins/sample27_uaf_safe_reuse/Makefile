CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_safe_reuse.exe
SRC = vuln_safe_reuse.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
