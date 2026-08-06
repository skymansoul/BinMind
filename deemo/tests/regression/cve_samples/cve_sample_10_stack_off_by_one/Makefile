CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_10_stack_off_by_one

all: $(TARGET)

$(TARGET): cve_sample_10_stack_off_by_one.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
