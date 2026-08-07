CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_struct_uaf.exe
SRC = vuln_struct_uaf.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
