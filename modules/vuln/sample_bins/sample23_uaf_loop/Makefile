CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_loop_uaf.exe
SRC = vuln_loop_uaf.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
