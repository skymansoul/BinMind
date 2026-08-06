CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_02_format_string

all: $(TARGET)

$(TARGET): cve_sample_02_format_string.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
