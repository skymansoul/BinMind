CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./$(TARGET) '%x.%x.%x.%x'
