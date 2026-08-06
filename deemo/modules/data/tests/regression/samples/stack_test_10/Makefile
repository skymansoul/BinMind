CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := stack_test_10_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
