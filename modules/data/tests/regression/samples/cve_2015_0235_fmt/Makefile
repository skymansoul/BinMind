CC ?= gcc
CFLAGS ?= -O0 -g -Wall
TARGET := cve_2015_0235_fmt_sample
all: $(TARGET)
$(TARGET): *.c
	$(CC) $(CFLAGS) -o $@ $^
clean:; rm -f $(TARGET)
