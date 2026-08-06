CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2023_0461_sample

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
