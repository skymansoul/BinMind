CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = int_overflow_calc

all: $(TARGET)
$(TARGET): int_overflow_calc.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
