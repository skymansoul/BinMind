CC = gcc
CFLAGS = -O0 -g -fno-stack-protector
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
