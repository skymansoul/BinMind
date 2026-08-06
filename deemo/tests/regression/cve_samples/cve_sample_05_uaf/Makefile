CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
TARGET = cve_sample_05_uaf

all: $(TARGET)

$(TARGET): cve_sample_05_uaf.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o
