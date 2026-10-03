CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = multi_chunk
all: $(TARGET)
$(TARGET): multi_chunk.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
