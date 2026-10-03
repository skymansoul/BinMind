CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln_elf.exe
SRC = vuln.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
