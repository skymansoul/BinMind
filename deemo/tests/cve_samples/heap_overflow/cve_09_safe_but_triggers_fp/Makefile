CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = safe_pattern_fp
all: $(TARGET)
$(TARGET): safe_pattern_fp.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
