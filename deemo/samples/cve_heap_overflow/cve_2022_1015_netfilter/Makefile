CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = nf_expr_overflow

all: $(TARGET)

$(TARGET): nf_expr_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
