CC ?= gcc
CFLAGS ?= -O0 -no-pie -fno-stack-protector -w
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
