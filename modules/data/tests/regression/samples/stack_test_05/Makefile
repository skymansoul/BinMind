CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := stack_test_05_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
