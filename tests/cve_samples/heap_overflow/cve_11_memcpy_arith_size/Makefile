CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = memcpy_arith
all: $(TARGET)
$(TARGET): memcpy_arith.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
