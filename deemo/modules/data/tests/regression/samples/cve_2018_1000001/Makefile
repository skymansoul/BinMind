CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2018_1000001_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm -f $(TARGET)
