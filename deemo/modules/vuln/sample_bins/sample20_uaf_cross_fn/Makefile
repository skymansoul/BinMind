CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = vuln_cross_fn_uaf.exe
SRC = vuln_cross_fn_uaf.c.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
