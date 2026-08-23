CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -lpthread
TARGET = canbcm_overflow

all: $(TARGET)

$(TARGET): canbcm_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
