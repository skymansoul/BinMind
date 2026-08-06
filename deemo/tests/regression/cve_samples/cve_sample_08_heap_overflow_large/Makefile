CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_08_heap_overflow_large

all: $(TARGET)

$(TARGET): cve_sample_08_heap_overflow_large.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
