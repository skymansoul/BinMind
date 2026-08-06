CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2022_0185_sample

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
