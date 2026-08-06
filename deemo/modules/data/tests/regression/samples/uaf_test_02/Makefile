CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := uaf_test_02_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
