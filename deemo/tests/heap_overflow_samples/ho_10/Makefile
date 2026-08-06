CC=gcc
CFLAGS=-O0 -g -w
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
# GENERIC-strcat CWE-787: strcat向固定大小缓冲区追加导致溢出
