CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2021_3156_sample

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
