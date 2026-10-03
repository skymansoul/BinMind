CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2015_8612_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
