CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -no-pie
TARGET=vuln_cve_2019_9213.elf
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET)
