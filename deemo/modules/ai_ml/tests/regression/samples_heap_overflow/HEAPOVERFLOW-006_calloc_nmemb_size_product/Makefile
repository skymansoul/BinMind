CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -no-pie -Wno-implicit-function-declaration
TARGET=target

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
