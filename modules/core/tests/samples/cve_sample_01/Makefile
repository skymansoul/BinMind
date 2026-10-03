CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -z execstack -no-pie
TARGET=vuln_cve_2020_29370.elf

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
