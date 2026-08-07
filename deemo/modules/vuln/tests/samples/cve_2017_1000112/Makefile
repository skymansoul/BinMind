CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector -z execstack
TARGET = vuln_udp_frag

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
