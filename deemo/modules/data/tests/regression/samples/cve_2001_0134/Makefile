CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2001_0134_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm -f $(TARGET)
