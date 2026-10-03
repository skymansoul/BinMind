CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = constrained_safe
all: $(TARGET)
$(TARGET): constrained_safe.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
