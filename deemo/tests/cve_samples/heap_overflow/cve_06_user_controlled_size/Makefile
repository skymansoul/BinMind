CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = user_ctrl_size
all: $(TARGET)
$(TARGET): user_ctrl_size.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
