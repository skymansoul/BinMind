CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_01_stack_overflow

all: $(TARGET)

$(TARGET): cve_sample_01_stack_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
