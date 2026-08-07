CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -m32  # -m32 用于模拟32位整数回绕
TARGET = lcms_overflow

all: $(TARGET)

$(TARGET): lcms_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
