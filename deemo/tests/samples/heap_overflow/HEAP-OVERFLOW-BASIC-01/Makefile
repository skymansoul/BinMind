CC       = gcc
CFLAGS   = -g -O0 -fno-stack-protector -z execstack
TARGET   = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
