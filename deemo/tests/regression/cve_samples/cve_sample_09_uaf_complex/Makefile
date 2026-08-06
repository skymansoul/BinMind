CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_09_uaf_complex

all: $(TARGET)

$(TARGET): cve_sample_09_uaf_complex.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
