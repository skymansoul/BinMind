CC = gcc
CFLAGS = -Wall -O0 -g -no-pie -fno-stack-protector -z execstack
TARGET = vuln

all: $(TARGET)

$(TARGET): src/vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
