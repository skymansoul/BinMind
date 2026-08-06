CC ?= gcc
CFLAGS ?= -g -O0
all: vuln.elf
vuln.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f *.elf
