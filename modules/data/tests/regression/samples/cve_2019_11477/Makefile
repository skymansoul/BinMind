CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2019_11477_sample

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
