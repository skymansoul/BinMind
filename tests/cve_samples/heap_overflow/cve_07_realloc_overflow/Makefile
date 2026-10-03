CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = realloc_overflow
all: $(TARGET)
$(TARGET): realloc_overflow.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
