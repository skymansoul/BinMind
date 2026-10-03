CC = gcc; CFLAGS = -Wall -O0 -g; TARGET = real_world
all: $(TARGET)
$(TARGET): real_world.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
