CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln_sudo

all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
