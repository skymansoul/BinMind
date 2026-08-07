CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = vuln
SRC = vuln.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) *.exe

.PHONY: all clean
