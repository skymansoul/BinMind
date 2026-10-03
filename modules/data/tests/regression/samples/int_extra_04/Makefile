CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := int_extra_04_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
