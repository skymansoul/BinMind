CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = calloc_overflow
all: $(TARGET)
$(TARGET): calloc_overflow.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
