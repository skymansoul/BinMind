CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-stack-protector -z execstack -no-pie
TARGET = sample

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
