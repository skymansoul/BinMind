CC=gcc
CFLAGS=-g -O0 -fno-stack-protector -z execstack -Wall
TARGET=vuln
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
