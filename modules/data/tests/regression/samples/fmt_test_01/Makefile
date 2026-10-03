CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := fmt_test_01_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
