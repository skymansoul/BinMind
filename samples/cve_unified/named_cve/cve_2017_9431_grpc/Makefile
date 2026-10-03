CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = grpc_overflow

all: $(TARGET)

$(TARGET): grpc_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
