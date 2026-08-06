CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2016_6187_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm -f $(TARGET)
