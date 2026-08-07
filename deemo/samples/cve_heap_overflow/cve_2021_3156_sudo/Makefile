CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = baron_samedit

all: $(TARGET)

$(TARGET): baron_samedit.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
