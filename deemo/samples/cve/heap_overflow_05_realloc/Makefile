CC=gcc
CFLAGS=-O0 -g -w -fno-stack-protector
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
