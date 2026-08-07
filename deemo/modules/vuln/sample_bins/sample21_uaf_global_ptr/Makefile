CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_global_uaf.exe
SRC = vuln_global_uaf.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
