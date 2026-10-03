CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2016_4484_sample

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
